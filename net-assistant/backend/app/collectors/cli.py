"""Explicit one-shot local collection and durable storage (never scans remote hosts)."""
import argparse
import json
from pathlib import Path
from uuid import UUID

from app.collectors.store import NetworkStore
from app.discovery.store import initialize_database


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--device-id", required=True, type=UUID)
    parser.add_argument("--label", required=True)
    parser.add_argument("--asset-id", type=UUID)
    args = parser.parse_args(argv)
    if not args.database.is_absolute():
        parser.error("--database must be absolute.")
    result = NetworkStore(initialize_database(args.database)).collect(
        args.device_id, args.label, asset_id=args.asset_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["state"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
