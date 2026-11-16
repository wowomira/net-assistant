"""Read-only verification. Backup restoration occurs only in a temporary directory.

Run with python -m scripts.verify_asset_registry from the backend project root.
No network probes, asset writes, migrations or replacement of the working DB.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile

from app.assets.service import AssetRegistry
from app.discovery.store import Database
from app.discovery.types import utc_now


def fingerprint(connection):
    result = {}
    for table in ("discovery_scopes", "discovery_jobs", "discovery_hosts", "discovery_probes"):
        # Compare original evidence across additive job-column migrations.
        columns = ("sequence,id,scope_id,scope_revision,state,started_at,finished_at,"
                   "config_snapshot,coverage,error_code") if table == "discovery_jobs" else "*"
        rows = connection.execute(f"SELECT {columns} FROM {table} ORDER BY id").fetchall()
        encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        result[table] = {"rows": len(rows), "sha256": hashlib.sha256(encoded).hexdigest()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    path = args.database.resolve()
    if args.output:
        protected = {item.resolve() for item in (args.database, args.backup, args.baseline) if item}
        if args.output.resolve() in protected or args.output.suffix.lower() != ".json":
            parser.error("--output must be a separate .json report, not an input file.")
    registry = AssetRegistry(Database(path, readonly=True))
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        assert integrity == [("ok",)] and foreign_keys == []
        discovery = fingerprint(connection)
        counts = {table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                  for table in ("assets", "asset_discovery_links", "asset_audit_events")}
        schema = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    original_unchanged = None
    if args.baseline:
        original_unchanged = discovery == json.loads(
            args.baseline.read_text(encoding="utf-8"))["discoveryBefore"]
        assert original_unchanged, "Original evidence differs from recorded baseline."
    restore_verified, backup_schema = False, None
    if args.backup:
        with tempfile.TemporaryDirectory(prefix="net-assistant-restore-") as folder:
            with closing(sqlite3.connect(args.backup.resolve().as_uri() + "?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(Path(folder) / "restored.sqlite")) as restored:
                    source.backup(restored)
                    assert restored.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
                    assert restored.execute("PRAGMA foreign_key_check").fetchall() == []
                    assert fingerprint(restored) == discovery
                    backup_schema = restored.execute(
                        "SELECT version_num FROM alembic_version").fetchone()[0]
                    restore_verified = True
    assets, cursor = [], None
    while True:
        page = registry.list_assets(limit=200, cursor=cursor)
        assets.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    for asset in assets:
        assert asset["collection_access"] == "not_enrolled" and asset["host_metrics"] is None
    result = {
        "verifiedAt": utc_now(), "database": str(path), "schemaVersion": schema,
        "integrityCheck": integrity, "foreignKeyCheck": foreign_keys,
        "discoveryFingerprint": discovery, "originalDiscoveryUnchanged": original_unchanged,
        "registryRowCounts": counts, "backupRestoreVerified": restore_verified,
        "backupSchemaVersion": backup_schema, "assets": assets,
        "note": "Historical observations only; no new target checks or collection authorization.",
    }
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
