"""Read-only, column-aware evidence snapshots across additive migrations.

This script never registers assets, starts scans, or changes the source database.
"""
import argparse
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


def snapshot(path, columns=None):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        tables = columns or {
            name: [r[1] for r in connection.execute(f'PRAGMA table_info("{name}")')]
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "AND name != 'alembic_version' ORDER BY name").fetchall()
        }
        result = {}
        for table, selected in tables.items():
            # Identifiers come from sqlite_master/our saved snapshot, never shell or request input.
            if not table.replace("_", "").isalnum() or any(
                    not key.replace("_", "").isalnum() for key in selected):
                raise ValueError("Invalid snapshot identifier.")
            projection = ",".join(f'"{key}"' for key in selected)
            rows = connection.execute(f'SELECT {projection} FROM "{table}" ORDER BY 1').fetchall()
            result[table] = {
                "columns": selected, "rows": len(rows),
                "sha256": sha256(json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(),
            }
        return {"schema": connection.execute("SELECT version_num FROM alembic_version").fetchone()[0],
                "tables": result, "integrity": "ok", "foreignKeys": "ok"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.suffix != ".json" or args.output.resolve() in {
        args.database.resolve(), args.baseline.resolve() if args.baseline else None,
    }:
        parser.error("Output must be a separate new JSON report.")
    result = snapshot(args.database)
    if args.baseline:
        before = json.loads(args.baseline.read_text(encoding="utf-8"))
        original = snapshot(args.database, {key: value["columns"] for key, value in before["tables"].items()})
        result["originalColumnsUnchanged"] = original["tables"] == before["tables"]
        assert result["originalColumnsUnchanged"], "Original database rows changed."
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
