"""Read local Windows networking, never VM metadata or remote machine internals."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess

from app.assets.service import canonical_mac
from app.collectors.contracts import Address, Interface, Neighbor, NetworkSnapshot
from app.discovery.types import safe_text, utc_now


def _rows(value):
    if value is None:
        return []
    return [value] if isinstance(value, dict) else value


def _address(value, index):
    address = ipaddress.ip_address(value)
    if address.version == 6 and address.is_link_local and not address.scope_id:
        return f"{address}%{index}"
    return str(address)


def normalize_network(raw):
    interfaces = []
    for adapter in _rows(raw["adapters"]):
        index = int(adapter["ifIndex"])
        addresses = [
            Address(address=_address(item["IPAddress"], index), prefix_length=item["PrefixLength"],
                    source="Get-NetIPAddress")
            for item in _rows(raw["addresses"]) if int(item["InterfaceIndex"]) == index
        ]
        interfaces.append(Interface(
            interface_index=index, name=safe_text(adapter["Name"], 256),
            description=safe_text(adapter.get("InterfaceDescription", ""), 256) or None,
            mac=canonical_mac(adapter.get("MacAddress")),
            state=safe_text(str(adapter.get("Status", "")), 64), addresses=addresses,
        ))
    known = {item.interface_index for item in interfaces}
    for item in _rows(raw["addresses"]):
        index = int(item["InterfaceIndex"])
        if index in known:
            continue
        # Loopback/tunnel IP interfaces need not have a Get-NetAdapter row.
        # The alias is a real Windows field, not a guessed target/VM identity.
        interfaces.append(Interface(
            interface_index=index, name=safe_text(item.get("InterfaceAlias", ""), 256),
            addresses=[Address(address=_address(row["IPAddress"], index),
                               prefix_length=row["PrefixLength"], source="Get-NetIPAddress")
                       for row in _rows(raw["addresses"]) if int(row["InterfaceIndex"]) == index],
        ))
        known.add(index)
    neighbors = [Neighbor(
        interface_index=int(item["InterfaceIndex"]),
        address=_address(item["IPAddress"], int(item["InterfaceIndex"])),
        mac=canonical_mac(item.get("LinkLayerAddress")), state=safe_text(str(item["State"]), 64),
    ) for item in _rows(raw["neighbors"])]
    return NetworkSnapshot(source="windows_native", observed_at=utc_now(),
                           interfaces=interfaces, neighbors=neighbors)


def collect_network():
    if os.name != "nt":
        raise RuntimeError("Windows native collector is unavailable on this platform.")
    executable = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # Fixed script, no untrusted interpolation and no remoting/credentials.
    script = """
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$adapters=@(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,Name,InterfaceDescription,MacAddress,@{n='Status';e={$_.Status.ToString()}})
$addresses=@(Get-NetIPAddress | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength)
$neighbors=@(Get-NetNeighbor | Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,@{n='State';e={$_.State.ToString()}})
@{adapters=$adapters;addresses=$addresses;neighbors=$neighbors} | ConvertTo-Json -Depth 6 -Compress
"""
    result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, timeout=30, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError("Local network output exceeds limit.")
    return normalize_network(json.loads(result.stdout.decode("utf-8-sig")))


def main():
    # Explicit one-shot local collection; does not store anything in the work DB.
    print(collect_network().model_dump_json(indent=2))


if __name__ == "__main__":
    main()
