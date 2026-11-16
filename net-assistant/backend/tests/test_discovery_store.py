import json
import sqlite3

import pytest

from app.discovery.config import ScanSettings
from app.discovery.store import Database, initialize_database
from app.discovery.types import ProbeResult


def test_migration_persistence_scope_revision_and_no_wal(tmp_path):
    path = tmp_path / "inspection.sqlite"
    db = initialize_database(path)
    settings = ScanSettings(name="test", targets=["10.1.1.1"], ports=[80], discovery_ports=[80])
    scope_id, revision = db.save_scope(settings)
    assert revision == 1
    assert db.save_scope(settings) == (scope_id, 1)
    changed = settings.model_copy(update={"timeout_ms": 700})
    assert db.save_scope(changed) == (scope_id, 2)
    job_id = db.begin_job(scope_id, 2, changed.snapshot())
    db.record_discovery(job_id, "10.1.1.1", [
        ProbeResult("10.1.1.1", "icmp", "reply", evidence={"roundTripMs": 2})
    ], {"discovery_methods": ["icmp"], "mac": None, "context": {}, "confidence": "direct_response"})
    db.finish_job(job_id, "completed", {"completedDiscoveryAddresses": 1})
    reopened = Database(path, readonly=True)
    assert reopened.get_job(job_id)["state"] == "completed"
    assert reopened.list_hosts(job_id)["items"][0]["address"] == "10.1.1.1"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()
    initialize_database(path)  # Migration is repeatable, not a destructive reset.
    assert Database(path, readonly=True).get_job(job_id)["state"] == "completed"


def test_progress_database_is_not_migrated_or_overwritten(tmp_path):
    path = tmp_path / "progress.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE progress(id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO progress VALUES ('keep-me')")
    with pytest.raises(ValueError, match="unrelated"):
        initialize_database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT id FROM progress").fetchall() == [("keep-me",)]
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name='alembic_version'"
        ).fetchall()


def test_readonly_database_does_not_create_missing_file(tmp_path):
    path = tmp_path / "missing.sqlite"
    db = Database(path, readonly=True)
    with pytest.raises(Exception):
        db.list_jobs()
    assert not path.exists()


def test_evidence_bound_pagination_and_stale_run_recovery(tmp_path):
    db = initialize_database(tmp_path / "test.sqlite")
    settings = ScanSettings(name="test", targets=["10.1.1.1"], ports=[80], discovery_ports=[80])
    scope_id, revision = db.save_scope(settings)
    job = db.begin_job(scope_id, revision, settings.snapshot())
    db.record_probes(job, [
        ProbeResult("10.1.1.1", "banner", "received", port=22, evidence={"banner": "x" * 10000}),
        ProbeResult("10.1.1.1", "tcp", "open", port=80),
    ])
    first = db.list_probes(job, limit=1)
    assert len(json.dumps(first["items"][0]["evidence"], ensure_ascii=False).encode()) <= 2048
    assert first["next_cursor"] is not None
    second = db.list_probes(job, limit=1, cursor=first["next_cursor"])
    assert first["items"][0]["id"] != second["items"][0]["id"]
    assert second["next_cursor"] is None
    assert db.interrupt_stale_jobs() == 1
    assert db.get_job(job)["state"] == "interrupted"


def test_persisted_unicode_evidence_respects_actual_utf8_storage_limit(tmp_path):
    path = tmp_path / "unicode.sqlite"
    db = initialize_database(path)
    settings = ScanSettings(name="unicode", targets=["10.1.1.1"], ports=[80])
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    db.record_probes(job, [
        ProbeResult("10.1.1.1", "banner", "received", port=80,
                    evidence={"banner": "测试" * 10000})
    ])
    with sqlite3.connect(path) as connection:
        stored, size = connection.execute(
            "SELECT evidence, length(CAST(evidence AS BLOB)) FROM discovery_probes"
        ).fetchone()
    assert size <= 2048
    assert json.loads(stored)["truncated"] is True
    assert "测试" in json.loads(stored)["preview"]


def test_backup_closes_native_connections_before_returning_on_windows(tmp_path):
    """A completed backup must be movable immediately, not after cyclic GC."""
    import gc
    import sys
    from app.discovery.store import backup_database
    if sys.platform != "win32":
        pytest.skip("Open-file rename denial is a Windows contract.")
    db = initialize_database(tmp_path / "source.sqlite")
    enabled = gc.isenabled()
    gc.disable()
    try:
        backup = backup_database(db.path)
        moved = backup.with_name("verified-post-task.sqlite")
        backup.rename(moved)  # An open SQLite handle previously raised WinError32.
        assert moved.exists() and not backup.exists()
    finally:
        if enabled:
            gc.enable()
        gc.collect()
