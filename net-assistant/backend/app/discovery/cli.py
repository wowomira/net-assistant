import argparse
import json
import os
from pathlib import Path
import sys

from app.discovery.config import DEFAULT_DATABASE, ROOT, load_settings
from app.discovery.context import verified_source_network
from app.discovery.execution import execute_scan
from app.discovery.report import write_report
from app.discovery.store import Database, ScanBusyError, initialize_database, scan_writer_lock


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Local authorized discovery; no remote scan-start API.")
    parser.add_argument("command", choices=["validate", "scan", "export"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--database", type=Path, default=Path(os.environ.get("INSPECT_DB", str(DEFAULT_DATABASE))))
    parser.add_argument("--report-dir", type=Path, default=ROOT / "reports")
    parser.add_argument("--job-id")
    args = parser.parse_args(argv)
    if not args.database.is_absolute():
        parser.error("--database must be an absolute path.")
    if args.command == "export":
        if not args.job_id:
            parser.error("export requires --job-id.")
        print(write_report(Database(args.database, readonly=True), args.job_id, args.report_dir))
        return
    if not args.config:
        parser.error("validate/scan requires --config.")
    settings = load_settings(args.config)
    source_network = verified_source_network(settings.source_address)
    print(json.dumps({
        "name": settings.name, "targets": settings.targets, "exclude": settings.exclude,
        "engine": settings.engine, "nmapOsDetection": settings.nmap_os_detection,
        "mdnsEnabled": settings.mdns_enabled,
        "mdnsInterfaceAddresses": settings.mdns_interface_addresses,
        "candidateAddresses": len(settings.addresses()), "ports": settings.ports,
        "tcpPortMode": settings.tcp_port_mode,
        "effectiveTcpPortCount": len(settings.effective_ports()),
        "inventoryPolicy": "all_authorized_addresses",
        "screenshotsEnabled": settings.screenshots_enabled,
        "sourceAddress": settings.source_address, "verifiedLocalNetwork": source_network,
        "concurrency": settings.concurrency, "timeoutMs": settings.timeout_ms,
        "budgetSeconds": settings.budget_seconds,
    }, ensure_ascii=False), flush=True)
    if args.command == "validate":
        print("VALID: no database created and no network probes sent.", flush=True)
        return

    def progress(stage, coverage):
        print(json.dumps({"stage": stage, "coverage": coverage}, ensure_ascii=False), flush=True)

    try:
        with scan_writer_lock(args.database):
            db = initialize_database(args.database)
            result = execute_scan(settings, db, args.report_dir, progress=progress)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            return 0 if db.get_job(result["jobId"])["state"] == "completed" else 1
    except ScanBusyError:
        print(json.dumps({"code": "scan_busy", "message": "已有扫描或台账写操作，请稍后重试。"},
                         ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
