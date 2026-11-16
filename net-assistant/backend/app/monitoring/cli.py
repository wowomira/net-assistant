"""Explicit local configuration generation; GET API never writes or starts Gatus."""
import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

from app.monitoring.client import GatusClient
from app.monitoring.config import load_plan, write_gatus_config
from app.discovery.config import ROOT


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "render", "status", "run"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--storage", type=Path)
    args = parser.parse_args(argv)
    plan = load_plan(args.config)
    if args.command == "run":
        from app.monitoring.runtime import run_gatus
        from app.runtime_tools import gatus_executable
        return run_gatus(plan, gatus_executable(ROOT),
                         args.storage or ROOT / "tools/gatus/runtime/gatus.sqlite")
    elif args.command == "render":
        if not args.output or not args.storage:
            parser.error("render requires --output and --storage.")
        write_gatus_config(plan, args.output, args.storage, urlsplit(plan.api_url).port)
        print(json.dumps({"status": "written", "file": str(args.output)}, ensure_ascii=False))
    elif args.command == "status":
        print(json.dumps(asyncio.run(GatusClient(plan).statuses()), ensure_ascii=False, indent=2))
    else:
        print(json.dumps({"status": "valid", "endpoints": len(plan.endpoints),
                          "networkRequests": 0, "source": "gatus"}, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
