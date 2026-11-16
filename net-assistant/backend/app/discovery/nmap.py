"""A constrained Nmap process and XML adapter, not a new scan/fingerprint engine."""
import asyncio
import ipaddress
import os
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

from app.discovery.config import ScanSettings
from app.discovery.types import safe_text


STATES = {"open": "open", "closed": "refused", "filtered": "filtered",
          "open|filtered": "open_or_filtered", "closed|filtered": "closed_or_filtered",
          "unfiltered": "unfiltered"}


def lookup_mac_vendor(mac, executable):
    from app.assets.service import canonical_mac
    normalized = canonical_mac(mac)
    if normalized is None or int(normalized[:2], 16) & 2:
        return None
    binary = shutil.which(executable) or executable
    database = Path(binary).resolve().parent / "nmap-mac-prefixes"
    if not database.is_file() or database.stat().st_size > 16 * 1024 * 1024:
        return None
    prefix = normalized.replace(":", "")[:6]
    with database.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.strip().split(None, 1)
            if len(fields) == 2 and fields[0].upper() == prefix:
                return {"name": safe_text(fields[1], 120), "source": "nmap_mac_prefixes",
                        "match_type": "prefix_match", "device_brand_confirmed": False}
    return None


def command_for(settings: ScanSettings, address: str) -> list[str]:
    if not settings.permits(address):
        raise ValueError("Nmap target outside authorized scope.")
    target = ipaddress.ip_address(address)
    if settings.source_address and ipaddress.ip_address(settings.source_address).version != target.version:
        raise ValueError("Nmap source and target address families must match.")
    args = [settings.nmap_path, "-sT", "-Pn", "-sV", "--version-light",
            "--max-retries", "1", "--max-parallelism", str(settings.concurrency),
            "--host-timeout", f"{settings.nmap_host_timeout_seconds}s", "-oX", "-",
            "-p", "1-65535" if settings.tcp_port_mode == "all" else ",".join(map(str, settings.ports))]
    if settings.nmap_os_detection:
        args.extend(["--privileged", "-O", "--osscan-limit"])
    else:
        args.append("--unprivileged")
    if target.version == 6:
        args.append("-6")
    if settings.source_address:
        args.extend(["-S", settings.source_address])
    # Never accept shell strings, NSE scripts, arbitrary flags, or DNS targets.
    return [*args, "--", address]


def parse_nmap(data: bytes, address: str, ports, *, os_requested=False) -> dict:
    if len(data) > 16 * 1024 * 1024 or b"<!ENTITY" in data.upper():
        raise ValueError("Nmap XML size/entity boundary.")
    # Standard Nmap DOCTYPE has no system identifier or internal subset.
    doctypes = re.findall(rb"<!DOCTYPE[^>]*>", data, re.I)
    if any(item.strip().lower() != b"<!doctype nmaprun>" for item in doctypes):
        raise ValueError("Unexpected XML doctype.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError("Incomplete Nmap XML.") from error
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap did not finish successfully.")
    hosts = root.findall("host")
    if len(hosts) != 1:
        raise ValueError("Nmap did not return exactly one completed target.")
    host = hosts[0]
    target = ipaddress.ip_address(address)
    found = [item for item in host.findall("address") if item.get("addrtype") in ("ipv4", "ipv6")]
    # Nmap can omit the IPv6 zone from XML; it is retained from the validated argv.
    if not any(int(ipaddress.ip_address(item.get("addr"))) == int(target)
               and ipaddress.ip_address(item.get("addr")).version == target.version for item in found):
        raise ValueError("Unexpected Nmap target.")
    expected = set(ports)
    records = {}
    for port in host.findall("ports/port"):
        number = int(port.get("portid"))
        state = port.find("state")
        if number not in expected or number in records or port.get("protocol") != "tcp" or state is None:
            raise ValueError("Unexpected or duplicate Nmap port.")
        raw_state = state.get("state")
        if raw_state not in STATES:
            raise ValueError("Unknown Nmap port state.")
        service = port.find("service")
        details = None
        if service is not None:
            confidence = int(service.get("conf", "0"))
            if not 0 <= confidence <= 10:
                raise ValueError("Invalid Nmap service confidence.")
            details = {
                "name": safe_text(service.get("name", ""), 80),
                "product": safe_text(service.get("product", ""), 120) or None,
                "version": safe_text(service.get("version", ""), 80) or None,
                "method": service.get("method", "table"), "confidence": confidence,
                "tunnel": service.get("tunnel"),
            }
        records[number] = {"status": STATES[raw_state], "raw_state": raw_state,
                           "reason": safe_text(state.get("reason", ""), 80), "service": details}
    missing = expected - records.keys()
    extra = host.findall("ports/extraports")
    if sum(int(item.get("count", "0")) for item in extra) != len(missing):
        raise ValueError("Incomplete Nmap port coverage.")
    if missing:
        if len(extra) != 1 or extra[0].get("state") not in STATES:
            raise ValueError("Ambiguous Nmap grouped port states.")
        raw_state = extra[0].get("state")
        for number in missing:
            records[number] = {"status": STATES[raw_state], "raw_state": raw_state,
                               "reason": "nmap_extraports", "service": None}
    mac = next((item for item in host.findall("address") if item.get("addrtype") == "mac"), None)
    from app.assets.service import canonical_mac
    normalized_mac = canonical_mac(mac.get("addr")) if mac is not None else None
    vendor = None
    if normalized_mac and not int(normalized_mac[:2], 16) & 2 and mac.get("vendor"):
        vendor = {"name": safe_text(mac.get("vendor"), 120), "source": "nmap_mac_prefix",
                  "match_type": "prefix_match", "device_brand_confirmed": False}
    names = [{"hostname": safe_text(item.get("name", ""), 253),
              "source": "nmap_" + safe_text(item.get("type", "unknown"), 32)}
             for item in host.findall("hostnames/hostname")[:8] if item.get("name")]
    os_candidates = []
    for item in host.findall("os/osmatch")[:8]:
        accuracy = int(item.get("accuracy", "0"))
        if not 0 <= accuracy <= 100:
            raise ValueError("Invalid Nmap OS accuracy.")
        os_candidates.append({"name": safe_text(item.get("name", ""), 200),
                              "accuracy": accuracy, "source": "nmap_os_fingerprint",
                              "confirmed": False})
    os_status, os_reason = "not_requested", None
    if os_candidates:
        os_status = "candidates"
    elif os_requested:
        # --osscan-limit may skip a host with no suitable open+closed TCP pair.
        # The absence of a candidate is never a confirmed "unknown operating system".
        states = {item["raw_state"] for item in records.values()}
        os_status = "no_match" if {"open", "closed"} <= states else "limited"
        os_reason = ("fingerprint_not_matched" if os_status == "no_match"
                     else "open_and_closed_tcp_not_observed")
    return {"version": safe_text(root.get("version", ""), 80), "ports": records,
            "responsive": any(item["status"] == "open" for item in records.values()),
            "mac": normalized_mac, "vendor_hint": vendor, "names": names,
            "os_candidates": os_candidates,
            "os_detection": {"status": os_status, "reason_code": os_reason,
                             "source": "nmap_os_fingerprint", "confirmed": False}}


async def scan_host(settings, address):
    args = command_for(settings, address)
    executable = shutil.which(args[0])
    if executable is None and not Path(args[0]).is_file():
        raise FileNotFoundError("Nmap executable is not installed/configured.")
    args[0] = executable or args[0]
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )

    async def read(stream, limit):
        chunks, size = [], 0
        while chunk := await stream.read(65536):
            size += len(chunk)
            if size > limit:
                raise ValueError("Nmap output limit exceeded.")
            chunks.append(chunk)
        return b"".join(chunks)

    readers = [asyncio.create_task(read(process.stdout, 16 * 1024 * 1024)),
               asyncio.create_task(read(process.stderr, 1024 * 1024))]
    try:
        async with asyncio.timeout(settings.nmap_host_timeout_seconds + 5):
            stdout, _ = await asyncio.gather(*readers)
            code = await process.wait()
        if code != 0:
            raise ValueError("Nmap process failed; no implicit native fallback.")
        return parse_nmap(stdout, address, settings.effective_ports(),
                          os_requested=settings.nmap_os_detection)
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
        for reader in readers:
            if not reader.done():
                reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
