import ipaddress
import json
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE = ROOT / "data" / "inspection.sqlite"
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]


def _expand(spec: str):
    if ":" in spec:
        # IPv6 is candidate-based, never a /64 or other subnet enumeration.
        if "/" in spec and not spec.endswith("/128"):
            raise ValueError("IPv6 requires explicit addresses or /128 candidates.")
        address = ipaddress.IPv6Address(spec.removesuffix("/128"))
        if address.scope_id and not address.scope_id.isdecimal():
            raise ValueError("IPv6 interface scope must be a numeric Windows interface index.")
        return iter([address])
    if "-" in spec:
        first, last = (ipaddress.IPv4Address(part.strip()) for part in spec.split("-", 1))
        if int(last) < int(first):
            raise ValueError("Address range ends before it starts.")
        return (ipaddress.IPv4Address(value) for value in range(int(first), int(last) + 1))
    network = ipaddress.IPv4Network(spec, strict=True)
    return network.hosts()


def _matches(address, spec: str) -> bool:
    if ":" in spec:
        return address.version == 6 and address == next(_expand(spec))
    if address.version != 4:
        return False
    if "-" in spec:
        first, last = (ipaddress.IPv4Address(part.strip()) for part in spec.split("-", 1))
        return int(first) <= int(address) <= int(last)
    return address in ipaddress.IPv4Network(spec, strict=True)


class ScanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    # Native scanner is archived, not an automatic fallback or selectable engine.
    engine: Literal["nmap"] = "nmap"
    nmap_path: str = Field(default="nmap", min_length=1, max_length=1024)
    nmap_os_detection: bool = False
    nmap_host_timeout_seconds: int = Field(default=60, ge=5, le=900)
    mdns_enabled: bool = False
    mdns_interface_addresses: list[str] = Field(default_factory=list)
    mdns_service_types: list[str] = Field(default_factory=lambda: [
        "_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
    ])
    targets: list[str] = Field(min_length=1)
    exclude: list[str] = Field(default_factory=list)
    ports: list[Port] = Field(min_length=1)
    discovery_ports: list[Port] = Field(default_factory=list)
    http_ports: list[Port] = Field(default_factory=list)
    https_ports: list[Port] = Field(default_factory=list)
    tls_ports: list[Port] = Field(default_factory=list)
    banner_ports: list[Port] = Field(default_factory=list)
    profile_name: str = "custom"
    source_address: str | None = None
    icmp_enabled: bool = True
    arp_enabled: bool = True
    # Thorough inventory never uses ping/ARP as a prerequisite for TCP checks.
    tcp_port_mode: Literal["configured", "all"] = "configured"
    hostname_enabled: bool = True
    netbios_enabled: bool = True
    passive_service_detection: bool = True
    http_body_limit: int = Field(default=32768, ge=1024, le=65536)
    screenshots_enabled: bool = False
    screenshot_timeout_ms: int = Field(default=10000, ge=1000, le=30000)
    timeout_ms: int = Field(default=800, ge=100, le=10000)
    concurrency: int = Field(default=6, ge=1, le=64)
    budget_seconds: float = Field(default=900, gt=0, le=86400)
    max_addresses: int = Field(default=4096, ge=1)
    allow_public: bool = False
    allow_loopback: bool = False

    @field_validator("ports", "discovery_ports", "http_ports", "https_ports", "tls_ports", "banner_ports")
    @classmethod
    def valid_ports(cls, values):
        if any(isinstance(port, bool) or not 1 <= port <= 65535 for port in values):
            raise ValueError("TCP ports must be between 1 and 65535.")
        return sorted(set(values))

    @field_validator("targets", "exclude")
    @classmethod
    def valid_ranges(cls, values):
        for value in values:
            iterator = _expand(value)
            next(iter(iterator), None)
        return values

    @field_validator("source_address")
    @classmethod
    def valid_source(cls, value):
        if value is not None:
            return str(ipaddress.ip_address(value))
        return value

    @model_validator(mode="after")
    def subsets(self) -> Self:
        for name in ("discovery_ports", "http_ports", "https_ports", "tls_ports", "banner_ports"):
            if self.tcp_port_mode != "all" and not set(getattr(self, name)).issubset(self.ports):
                raise ValueError(f"{name} must be a subset of ports.")
        if self.mdns_enabled:
            if self.engine != "nmap" or not self.mdns_interface_addresses or not self.mdns_service_types:
                raise ValueError("mDNS requires Nmap, explicit local interfaces and service types.")
            for address in self.mdns_interface_addresses:
                ipaddress.ip_address(address)
            import re
            if len(self.mdns_service_types) > 16 or any(
                    not re.fullmatch(r"_[a-zA-Z0-9-]{1,63}\._(?:tcp|udp)\.local\.", value)
                    for value in self.mdns_service_types):
                raise ValueError("Invalid or excessive mDNS service types.")
        return self

    def addresses(self) -> list[str]:
        result = set()
        for spec in self.targets:
            if ":" in spec:
                expanded_size = 1
            elif "-" in spec:
                first, last = (ipaddress.IPv4Address(part.strip()) for part in spec.split("-", 1))
                expanded_size = int(last) - int(first) + 1
            else:
                network = ipaddress.IPv4Network(spec, strict=True)
                expanded_size = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
            if expanded_size > self.max_addresses:
                raise ValueError("Expanded range exceeds max_addresses before exclusions.")
            for address in _expand(spec):
                if any(_matches(address, excluded) for excluded in self.exclude):
                    continue
                if len(result) >= self.max_addresses and str(address) not in result:
                    raise ValueError("Expanded range exceeds max_addresses; narrow the scope or raise its explicit budget.")
                if address.version == 6 and self.engine != "nmap":
                    raise ValueError("IPv6 candidates require the Nmap engine.")
                if (address.is_multicast or address.is_unspecified
                        or (address.is_reserved and not address.is_loopback)
                        or (address.is_link_local and (address.version != 6 or not address.scope_id))):
                    raise ValueError(f"Not an allowed unicast target: {address}")
                if address.is_loopback:
                    if not self.allow_loopback:
                        raise ValueError("Loopback targets require allow_loopback.")
                elif not address.is_private and not self.allow_public:
                    raise ValueError("Public targets require explicit allow_public.")
                result.add(str(address))
        if not result:
            raise ValueError("No targets remain after exclusions.")
        return sorted(result, key=address_sort_key)

    def permits(self, address: str) -> bool:
        return address in self.addresses()

    def effective_ports(self):
        return range(1, 65536) if self.tcp_port_mode == "all" else self.ports

    def snapshot(self) -> dict:
        return self.model_dump(mode="json")


def load_settings(path: Path) -> ScanSettings:
    path = Path(path).resolve()
    values = json.loads(path.read_text(encoding="utf-8-sig"))
    profile_path = values.pop("port_profile", None)
    if profile_path:
        profile = json.loads((path.parent / profile_path).read_text(encoding="utf-8-sig"))
        values.setdefault("profile_name", profile.pop("name"))
        profile.pop("description", None)
        profile.pop("categories", None)
        values = {**profile, **values}
    settings = ScanSettings.model_validate(values)
    settings.addresses()  # Validate full scope before making any network requests.
    return settings


def address_sort_key(value):
    address = ipaddress.ip_address(value)
    return address.version, int(address), getattr(address, "scope_id", None) or ""


def url_host(address):
    return f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
