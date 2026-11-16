"""Read-only projections of persisted evidence, never port-number assertions."""
import re

from app.discovery.config import url_host
from app.discovery.types import safe_text


PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 27017: "mongodb",
}


def _banner_service(evidence):
    text = evidence.get("banner", "")
    if not isinstance(text, str):
        return None
    match = re.search(r"(?:^|\n)SSH-\d+\.\d+-([^\r\n ]+)", text)
    if match:
        software = match[1]
        product, _, version = software.partition("_")
        return "ssh", safe_text(product, 80), safe_text(version, 80) or None
    if text.startswith("RFB ") and re.match(r"RFB \d{3}\.\d{3}", text):
        return "vnc", None, text[4:11]
    if text.startswith("220") and re.search(r"\b(?:E?SMTP)\b", text, re.I):
        return "smtp", None, None
    if text.startswith("220") and re.search(r"\bFTP\b", text, re.I):
        return "ftp", None, None
    if text.startswith("+OK") and re.search(r"\bPOP3?\b", text, re.I):
        return "pop3", None, None
    if text.startswith("* OK") and re.search(r"\bIMAP", text, re.I):
        return "imap", None, None
    if evidence.get("protocol") == "mysql":
        return "mysql", evidence.get("product"), evidence.get("version")
    return None


def summarize_inventory(address, rows, snapshot):
    names = [row for row in rows if row["method"] == "name"]
    resolved = next((row for row in reversed(names) if row["status"] == "resolved"
                     and row["evidence"].get("hostname")), None)
    arp = [row for row in rows if row["method"] == "arp"]
    tcp = {row["port"]: row for row in rows if row["method"] == "tcp" and row["phase"] == "inventory"}
    expected = 65535 if snapshot.get("tcp_port_mode") == "all" else len(snapshot.get("ports", []))
    counts = {status: sum(row["status"] == status for row in tcp.values())
              for status in ("open", "refused", "timeout", "unreachable", "error",
                             "filtered", "open_or_filtered", "closed_or_filtered", "unfiltered")}
    summary = {
        "hostname": resolved["evidence"]["hostname"] if resolved else None,
        "hostname_source": resolved["evidence"].get("source") if resolved else None,
        "name_status": resolved["status"] if resolved else names[-1]["status"] if names else "not_collected",
        "mac_status": arp[-1]["status"] if arp else "not_collected",
        "port_scan": {
            "scope": snapshot.get("tcp_port_mode", "configured"), "planned": expected,
            "attempted": len(tcp), **counts, "unattempted": max(0, expected - len(tcp)),
            "complete": len(tcp) == expected and not counts["error"],
        },
        "services": [], "websites": [],
        "name_candidates": [row["evidence"] for row in names if row["status"] == "resolved"],
        "vendor_hint": next((row["evidence"] for row in reversed(rows)
                             if row["method"] == "vendor" and row["status"] == "hint"), None),
        "os_candidates": [row["evidence"] for row in rows if row["method"] == "os"
                          and row["status"] == "candidate"],
        "os_detection": next((row["evidence"] for row in reversed(rows)
                              if row["method"] == "nmap_os"), {"status": "not_collected"}),
    }
    by_port = {}
    for row in rows:
        if row["phase"] == "enrichment" and row["port"] is not None:
            by_port.setdefault(row["port"], []).append(row)
    for port, check in sorted(tcp.items()):
        if check["status"] != "open":
            continue
        evidence_rows = by_port.get(port, [])
        http = [row for row in evidence_rows if row["method"] == "http"]
        tls = next((row for row in reversed(evidence_rows) if row["method"] == "tls"), None)
        service = {"port": port, "transport": "tcp", "protocol": None, "product": None,
                   "version": None, "identification": "unknown", "port_hint": PORT_HINTS.get(port),
                   "evidence_methods": []}
        for row in evidence_rows:
            if row["method"] == "nmap_service" and row["status"] == "identified":
                evidence = row["evidence"]
                probed = evidence.get("method") == "probed"
                service.update(
                    protocol=evidence.get("name") if probed else None,
                    product=evidence.get("product") if probed else None,
                    version=evidence.get("version") if probed else None,
                    identification="observed" if probed else "port_table_hint",
                    port_hint=evidence.get("name") or service["port_hint"],
                    detection_method=evidence.get("method"),
                    tool_confidence=evidence.get("confidence"), evidence_methods=["nmap_service"],
                )
            if row["method"] == "banner" and row["status"] == "received":
                identified = _banner_service(row["evidence"])
                if identified:
                    service.update(zip(("protocol", "product", "version"), identified))
                    service["identification"] = "observed"
                    service["evidence_methods"].append("banner")
        for row in http:
            evidence = row["evidence"]
            scheme = evidence.get("scheme", "http")
            if row["status"] == "response":
                service.update(protocol=scheme, identification="observed")
                service["evidence_methods"].append("http")
                server = evidence.get("headers", {}).get("server")
                if server:
                    product, _, version = server.partition("/")
                    service.update(product=product, version=version or None)
            screenshot_row = next((item for item in reversed(evidence_rows)
                                   if item["method"] == "screenshot"
                                   and item["evidence"].get("scheme") == scheme), None)
            enabled = snapshot.get("screenshots_enabled", False)
            shot = {"status": "not_collected" if enabled else "not_requested", "captured_at": None,
                    "probe_id": None, "reason_code": "screenshot_not_completed" if enabled else None}
            if screenshot_row:
                shot.update(status=screenshot_row["status"],
                            captured_at=screenshot_row["observed_at"] if screenshot_row["status"] == "captured" else None,
                            probe_id=screenshot_row["id"] if screenshot_row["status"] == "captured" else None,
                            reason_code=screenshot_row["reason_code"])
            summary["websites"].append({
                "url": f"{scheme}://{url_host(address)}:{port}/", "scheme": scheme, "port": port,
                "status": row["status"], "status_code": evidence.get("statusCode"),
                "title": evidence.get("title"), "server": evidence.get("headers", {}).get("server"),
                "redirect_location": evidence.get("redirectLocation"),
                "tls_status": tls["status"] if tls else (
                    "verified" if scheme == "https" and row["status"] == "response" else
                    "certificate_error" if row["status"] == "certificate_error" else "not_checked"),
                "duration_ms": row["duration_ms"], "observed_at": row["observed_at"],
                "screenshot": shot,
            })
        if tls and tls["status"] == "verified" and service["protocol"] is None:
            service.update(protocol="tls", identification="observed", evidence_methods=["tls"])
        summary["services"].append(service)
    return summary
