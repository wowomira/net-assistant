"""Local registry writes only; this module never imports or starts network probes."""
import argparse
import json
import os
from pathlib import Path
import sys

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.assets.service import AssetRegistry, RegistryError
from app.discovery.config import DEFAULT_DATABASE
from app.discovery.store import Database, initialize_database, scan_writer_lock


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Local asset registration, explicit links and audit. No scanning.")
    parser.add_argument("--database", type=Path,
                        default=Path(os.environ.get("INSPECT_DB", str(DEFAULT_DATABASE))))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="Upgrade the inspection DB, backing up an existing old schema first.")
    listing = sub.add_parser("list")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--cursor")
    for name in ("show", "observations", "audit"):
        part = sub.add_parser(name)
        part.add_argument("--asset-id", required=True)
        if name != "show":
            part.add_argument("--limit", type=int, default=50)
            part.add_argument("--cursor")
    part = sub.add_parser("suggest")
    part.add_argument("--host-id", required=True)
    register = sub.add_parser("register")
    register.add_argument("--host-id", required=True)
    register.add_argument("--name", required=True)
    register.add_argument("--kind", default="unknown")
    register.add_argument("--owner")
    register.add_argument("--notes", default="")
    register.add_argument("--reason", required=True)
    for name in ("link", "unlink", "update"):
        part = sub.add_parser(name)
        part.add_argument("--asset-id", required=True)
        part.add_argument("--expected-revision", type=int, required=True)
        part.add_argument("--reason", required=True)
        if name != "update":
            part.add_argument("--host-id", required=True)
        else:
            part.add_argument("--name", default=argparse.SUPPRESS)
            part.add_argument("--kind", default=argparse.SUPPRESS)
            owner = part.add_mutually_exclusive_group()
            owner.add_argument("--owner", default=argparse.SUPPRESS)
            owner.add_argument("--clear-owner", action="store_true")
            part.add_argument("--notes", default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.database.is_absolute():
        parser.error("--database must be an absolute path.")

    def execute(db):
        registry = AssetRegistry(db)
        match args.command:
            case "migrate":
                return {"status": "migrated", "database": str(args.database)}
            case "list":
                return registry.list_assets(args.limit, args.cursor)
            case "show":
                return registry.get_asset(args.asset_id)
            case "observations":
                return registry.list_observations(args.asset_id, args.limit, args.cursor)
            case "audit":
                return registry.list_audit(args.asset_id, args.limit, args.cursor)
            case "suggest":
                return registry.association(args.host_id)
            case "register":
                return registry.register(args.host_id, name=args.name, asset_kind=args.kind,
                                         owner=args.owner, notes=args.notes, reason=args.reason)
            case "link" | "unlink":
                return getattr(registry, args.command)(
                    args.asset_id, args.host_id, expected_revision=args.expected_revision, reason=args.reason)
            case "update":
                changes = {key: getattr(args, key) for key in ("name", "owner", "notes") if hasattr(args, key)}
                if hasattr(args, "kind"):
                    changes["asset_kind"] = args.kind
                if args.clear_owner:
                    changes["owner"] = None
                return registry.update(args.asset_id, expected_revision=args.expected_revision,
                                       reason=args.reason, **changes)

    try:
        if args.command in ("migrate", "register", "link", "unlink", "update"):
            with scan_writer_lock(args.database):
                result = execute(initialize_database(args.database))
        else:
            result = execute(Database(args.database, readonly=True))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except RegistryError as error:
        payload = {"code": error.code, "message": error.message}
    except ValidationError as error:
        payload = {"code": "validation_error", "message": "输入不符合台账约定。",
                   "fields": [{"field": ".".join(map(str, item["loc"])), "message": item["msg"]}
                              for item in error.errors()]}
    except SQLAlchemyError:
        payload = {"code": "database_unavailable", "message": "数据库不可用或尚未升级，请检查路径与迁移。"}
    except OSError:
        payload = {"code": "storage_or_writer_busy", "message": "存储不可访问或已有扫描/台账写入者，请稍后重试。"}
    except ValueError as error:
        payload = {"code": "invalid_configuration", "message": str(error)}
    print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
