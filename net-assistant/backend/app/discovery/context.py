import ipaddress
import json
import os
from pathlib import Path
import subprocess


def verified_source_network(source_address: str | None) -> str | None:
    # 只核对管理端实际网卡，用于绑定源地址和判断同链路 ARP；不读取目标或虚拟机文件。
    if source_address is None:
        return None
    if os.name != "nt":
        raise ValueError("Source interface validation is currently implemented for the Windows manager only.")
    executable = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(executable), "-NoProfile", "-NonInteractive", "-Command",
         "Get-NetIPAddress | Select-Object IPAddress,PrefixLength,InterfaceIndex | ConvertTo-Json -Compress"],
        capture_output=True, text=True, timeout=20, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    rows = json.loads(result.stdout)
    if isinstance(rows, dict):
        rows = [rows]
    source = ipaddress.ip_address(source_address)
    row = next((item for item in rows if int(ipaddress.ip_address(item["IPAddress"])) == int(source)
                and ipaddress.ip_address(item["IPAddress"]).version == source.version
                and (not getattr(source, "scope_id", None)
                     or str(item["InterfaceIndex"]) == source.scope_id)), None)
    if row is None:
        raise ValueError("Configured source_address is not an address on this manager.")
    return str(ipaddress.ip_network(f'{source_address.split("%")[0]}/{row["PrefixLength"]}', strict=False))
