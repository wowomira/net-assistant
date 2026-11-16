import ipaddress
import json
from hashlib import sha256
from pathlib import Path
from contextlib import closing
import sqlite3
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    url: str = Field(max_length=2048)
    asset_id: UUID | None = None  # Explicit operator mapping, never inferred from an IP.
    interval_seconds: int = Field(default=60, ge=5, le=86400)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    response_time_ms: int = Field(default=2000, ge=1, le=30000)
    status_code: int = Field(default=200, ge=100, le=599)
    certificate_days: int | None = Field(default=None, ge=1, le=365)

    @model_validator(mode="after")
    def validate_url(self):
        u = urlsplit(self.url)
        if (u.scheme not in ("http", "https", "tcp") or not u.hostname
                or u.username is not None or u.password is not None or u.query or u.fragment
                or any(ord(ch) < 33 for ch in self.url) or "$" in self.url):
            raise ValueError("Only approved HTTP/HTTPS/TCP URLs without credentials, query, fragments or templates.")
        if u.port is not None and not 1 <= u.port <= 65535:
            raise ValueError("Invalid endpoint port.")
        if u.scheme == "tcp" and (not u.port or u.path not in ("", "/")):
            raise ValueError("TCP endpoints require a port and no application path.")
        if self.certificate_days is not None and u.scheme != "https":
            raise ValueError("Certificate conditions require HTTPS.")
        if self.timeout_seconds > self.interval_seconds:
            raise ValueError("Timeout cannot exceed monitoring interval.")
        return self

    @property
    def gatus_name(self):
        # Upstream statuses have no URL or check configuration. Bind their key to
        # that configuration so editing a plan cannot relabel old samples as
        # healthy observations of a different target or a different condition.
        health = self.model_dump(mode="json", exclude={"id", "asset_id"})
        digest = sha256(json.dumps(health, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
        return f"{self.id}-{digest}"

    @property
    def key(self):
        return "net-assistant_" + self.gatus_name


class MonitoringPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # No URL from a browser request is ever used as the upstream API address.
    api_url: str = "http://127.0.0.1:18080"
    allowed_hosts: list[str] = Field(default_factory=list, max_length=200)
    allow_public: bool = False
    allow_loopback: bool = False
    endpoints: list[Endpoint] = Field(default_factory=list, max_length=200)

    @field_validator("api_url")
    @classmethod
    def local_api_only(cls, value):
        u = urlsplit(value)
        if (u.scheme != "http" or u.hostname not in ("127.0.0.1", "::1")
                or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment):
            raise ValueError("Gatus API must be an explicit local loopback HTTP address.")
        if u.port is None:
            raise ValueError("Gatus API needs an explicit port.")
        return value.rstrip("/")

    @model_validator(mode="after")
    def approved_targets(self):
        if len({endpoint.id for endpoint in self.endpoints}) != len(self.endpoints):
            raise ValueError("Duplicate monitoring endpoint id.")
        for endpoint in self.endpoints:
            host = urlsplit(endpoint.url).hostname
            if host not in self.allowed_hosts:
                raise ValueError("Monitoring host is outside the explicitly approved scope.")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                # Domain approval is explicit; allow_public makes its DNS boundary
                # visible rather than pretending that an IP scope constrains DNS.
                if not self.allow_public:
                    raise ValueError("Domain monitoring requires explicit allow_public and exact allowed_hosts.")
                continue
            if address.is_multicast or address.is_unspecified:
                raise ValueError("Not a unicast monitoring target.")
            if address.is_loopback:
                if not self.allow_loopback:
                    raise ValueError("Loopback monitoring requires allow_loopback.")
            elif address.is_link_local or address.is_reserved:
                raise ValueError("Link-local/reserved monitoring targets are not supported.")
            elif not address.is_private and not self.allow_public:
                raise ValueError("Public monitoring requires allow_public.")
        return self


def load_plan(path: Path) -> MonitoringPlan:
    return MonitoringPlan.model_validate_json(Path(path).read_text(encoding="utf-8-sig"))


def render_gatus(plan: MonitoringPlan, storage: Path, port: int) -> dict:
    if not plan.endpoints:
        raise ValueError("At least one explicitly approved endpoint is required to run Gatus.")
    if not storage.is_absolute() or storage.suffix != ".sqlite":
        raise ValueError("Gatus requires a dedicated absolute .sqlite storage path.")
    # Never point the monitor at an inspection DB, even by an accidental CLI option.
    if storage.name == "inspection.sqlite":
        raise ValueError("Gatus storage must not be the asset/discovery database.")
    if "$" in str(storage):
        raise ValueError("Gatus storage path cannot contain environment expansion.")
    if storage.exists():
        allowed = {"suites", "suite_results", "endpoints", "endpoint_events", "endpoint_results",
                   "endpoint_result_conditions", "endpoint_uptimes", "endpoint_alerts_triggered",
                   "sqlite_sequence"}
        try:
            with closing(sqlite3.connect(storage.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {"endpoints", "endpoint_results"} <= names or names - allowed:
                    raise ValueError("Refusing to use a non-Gatus database.")
                for table, expected in {
                    "endpoints": {"endpoint_id", "endpoint_key", "endpoint_name", "endpoint_group"},
                    "endpoint_results": {"endpoint_result_id", "endpoint_id", "success", "duration", "timestamp"},
                }.items():
                    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
                    if not expected <= columns:
                        raise ValueError("Refusing a database without the expected Gatus schema.")
        except sqlite3.Error as error:
            raise ValueError("Gatus storage is not a readable dedicated SQLite database.") from error
    if not 1024 <= port <= 65535 or urlsplit(plan.api_url).port != port:
        raise ValueError("Gatus web port must match the approved API URL.")
    if urlsplit(plan.api_url).hostname != "127.0.0.1":
        raise ValueError("Generated Gatus listener currently uses IPv4 loopback.")
    endpoints = []
    for endpoint in plan.endpoints:
        scheme = urlsplit(endpoint.url).scheme
        conditions = ["[CONNECTED] == true" if scheme == "tcp"
                      else f"[STATUS] == {endpoint.status_code}",
                      f"[RESPONSE_TIME] < {endpoint.response_time_ms}"]
        if endpoint.certificate_days is not None:
            conditions.append(f"[CERTIFICATE_EXPIRATION] > {endpoint.certificate_days * 24}h")
        endpoints.append({
            "name": endpoint.gatus_name, "group": "net-assistant", "url": endpoint.url,
            "interval": f"{endpoint.interval_seconds}s", "conditions": conditions,
            "client": {"insecure": False, "ignore-redirect": True,
                       "timeout": f"{endpoint.timeout_seconds}s"},
        })
    return {
        "web": {"address": "127.0.0.1", "port": port}, "metrics": False,
        "storage": {"type": "sqlite", "path": storage.as_posix(),
                    "maximum-number-of-results": 100, "maximum-number-of-events": 50},
        "concurrency": 3, "endpoints": endpoints,
    }


def write_gatus_config(plan, output: Path, storage: Path, port: int):
    config = render_gatus(plan, storage, port)
    # JSON is a YAML subset accepted by Gatus; no extra YAML parser is needed.
    # Exclusive creation refuses to overwrite a running monitor's configuration.
    with Path(output).open("x", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
