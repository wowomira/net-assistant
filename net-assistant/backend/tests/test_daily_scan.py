"""Daily scheduling uses artificial clocks and a real, independent SQLite file."""
import asyncio
from datetime import datetime, timezone
import json
import sqlite3
import subprocess
import sys

import pytest

from app.discovery.config import ScanSettings
from legacy_native.runner import run_discovery
from app.discovery.store import Database, initialize_database, scan_writer_lock
from app.discovery.types import ProbeResult


def plan_at(tmp_path):
    from app.scheduling.config import DailyPlan
    config = tmp_path / "scope.json"
    config.write_text(json.dumps({"name": "daily-test", "targets": ["10.17.0.10"], "ports": [80]}),
                      encoding="utf-8")
    return DailyPlan(name="daily-lab", at="09:00", utc_offset_minutes=480,
                     scan_config=config, database=tmp_path / "daily.sqlite",
                     report_directory=tmp_path / "reports")


def fake_network_executor(plan, db, run_id):
    """Only the transport is artificial; real runner, identity and persistence."""
    class Probes:
        async def icmp(self, address):
            return ProbeResult(address, "icmp", "reply")

        async def arp(self, address):
            return ProbeResult(address, "arp", "resolved", evidence={"mac": "00:11:22:33:44:55"})

        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "open", port=port)
    settings = ScanSettings(name="daily-test", targets=["10.17.0.10"], ports=[80])
    job_id = asyncio.run(run_discovery(settings, db, Probes(), trigger="scheduled", schedule_run_id=run_id))
    return {"jobId": job_id}


def test_not_due_or_disabled_never_opens_db_or_scans(tmp_path):
    from app.scheduling.service import run_due
    plan = plan_at(tmp_path)
    assert run_due(plan, now=datetime(2026, 11, 15, 0, 59, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "not_due"
    assert not plan.database.exists()
    plan.enabled = False
    assert run_due(plan, now=datetime(2026, 11, 15, 2, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "disabled"
    assert not plan.database.exists()


def test_at_nine_once_per_beijing_date_and_next_day_runs_again(tmp_path):
    from app.scheduling.service import run_due
    from app.assets.service import AssetRegistry
    plan = plan_at(tmp_path)
    result = run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc),
                     executor=fake_network_executor)
    assert result["status"] == "completed" and result["localDate"] == "2026-11-15"
    assert run_due(plan, now=datetime(2026, 11, 15, 15, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "already_attempted"
    assert run_due(plan, now=datetime(2026, 11, 16, 1, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "completed"
    db = Database(plan.database, readonly=True)
    assert len(db.list_jobs()["items"]) == 2
    assert all(job["trigger"] == "scheduled" and job["schedule_run_id"] for job in db.list_jobs()["items"])
    assets = AssetRegistry(db).list_assets()["items"]
    assert len(assets) == 1 and assets[0]["linked_observation_count"] == 2


def test_manual_scan_does_not_consume_daily_slot(tmp_path):
    from app.scheduling.service import run_due
    plan = plan_at(tmp_path)
    db = initialize_database(plan.database)
    scope, rev = db.save_scope(ScanSettings(name="manual", targets=["10.17.0.10"], ports=[80]))
    manual = db.begin_job(scope, rev, {})
    db.finish_job(manual, "completed", {})
    result = run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc),
                     executor=fake_network_executor)
    assert result["status"] == "completed"
    assert [j["trigger"] for j in db.list_jobs()["items"]] == ["manual", "scheduled"]


def test_busy_manual_scan_does_not_consume_daily_slot(tmp_path):
    from app.scheduling.service import run_due
    plan = plan_at(tmp_path)
    with scan_writer_lock(plan.database):
        result = run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc),
                         executor=fake_network_executor)
    assert result["status"] == "busy"
    assert not plan.database.exists()
    assert run_due(plan, now=datetime(2026, 11, 15, 1, 10, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "completed"


def test_failed_scan_is_recorded_not_repeated_infinitely(tmp_path):
    from app.scheduling.service import run_due, history
    plan = plan_at(tmp_path)

    def broken(plan, db, run_id):
        raise RuntimeError("test transport failure")

    result = run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc), executor=broken)
    assert result["status"] == "failed"
    runs = history(Database(plan.database, readonly=True))
    assert runs["items"][0]["state"] == "failed"
    assert runs["items"][0]["error_code"] == "scan_execution_failed"
    assert run_due(plan, now=datetime(2026, 11, 15, 2, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "already_attempted"


def test_process_crash_recovers_running_run_and_job_without_same_day_rescan(tmp_path):
    from app.scheduling.service import run_due, history
    from app.scheduling.models import ScheduledRunRow
    from sqlalchemy.orm import Session
    plan = plan_at(tmp_path)
    db = initialize_database(plan.database)
    with Session(db.engine) as session, session.begin():
        session.add(ScheduledRunRow(id="crashed-run", schedule_name=plan.name, local_date="2026-11-15",
                                   state="running", started_at="2026-11-15T01:00:00Z",
                                   finished_at=None, error_code=None, config_snapshot={}))
    scope, revision = db.save_scope(ScanSettings(name="daily-test", targets=["10.17.0.10"], ports=[80]))
    job = db.begin_job(scope, revision, {}, trigger="scheduled", schedule_run_id="crashed-run")
    result = run_due(plan, now=datetime(2026, 11, 15, 2, tzinfo=timezone.utc),
                     executor=fake_network_executor)
    assert result["status"] == "already_attempted"
    assert db.get_job(job)["state"] == "interrupted"
    assert history(db)["items"][0]["state"] == "interrupted"


def test_late_login_only_catches_up_today_not_a_backlog(tmp_path):
    from app.scheduling.service import run_due, history
    plan = plan_at(tmp_path)
    assert run_due(plan, now=datetime(2026, 11, 20, 14, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "completed"
    rows = history(Database(plan.database, readonly=True))["items"]
    assert len(rows) == 1 and rows[0]["local_date"] == "2026-11-20"


def test_schedule_config_resolves_relative_paths_and_rejects_invalid_values(tmp_path):
    from app.scheduling.config import load_plan, DailyPlan
    from pydantic import ValidationError
    config = tmp_path / "schedule.json"
    config.write_text(json.dumps({
        "name": "lab", "at": "09:00", "utc_offset_minutes": 480,
        "scan_config": "scope.json", "database": "../data/test.sqlite",
        "report_directory": "../reports",
    }), encoding="utf-8")
    plan = load_plan(config)
    assert plan.scan_config == tmp_path / "scope.json"
    assert plan.database == (tmp_path.parent / "data/test.sqlite").resolve()
    for changes in ({"at": "24:00"}, {"utc_offset_minutes": 9999}, {"database": "relative.sqlite"}):
        with pytest.raises(ValidationError):
            DailyPlan.model_validate({**plan.model_dump(), **changes})
    with pytest.raises(ValueError, match="aware"):
        from app.scheduling.service import run_due
        run_due(plan, now=datetime(2026, 11, 15, 9))


def test_status_command_is_read_only_and_missing_db_is_not_created(tmp_path):
    from app.discovery.config import ROOT
    config = tmp_path / "schedule.json"
    plan = plan_at(tmp_path)
    config.write_text(plan.model_dump_json(), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "app.scheduling.cli", "status", "--config", str(config)],
                            cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["databaseInitialized"] is False
    assert not plan.database.exists()


def test_database_upgrade_preserves_old_asset_metadata_and_new_schema_matches_models(tmp_path):
    from alembic import command
    from alembic.config import Config
    from app.discovery.config import ROOT
    from sqlalchemy import inspect
    from app.discovery.models import Base
    path = tmp_path / "old-0002.sqlite"
    db = Database(path)
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with db.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, "0002_asset_registry")
    db = initialize_database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    inspector = inspect(db.engine)
    for table in Base.metadata.sorted_tables:
        assert {c["name"] for c in inspector.get_columns(table.name)} == set(table.columns.keys())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows scheduled-task integration")
def test_windows_preview_builds_real_hidden_action_without_registering(tmp_path):
    from app.discovery.config import ROOT
    plan = plan_at(tmp_path)
    config = tmp_path / "schedule with spaces.json"
    # Preview's host-offset safeguard is real; make this test independent of
    # whether the clean Windows runner is configured for UTC or Asia/Shanghai.
    plan = plan.model_copy(update={
        "utc_offset_minutes": int(datetime.now().astimezone().utcoffset().total_seconds() / 60)
    })
    config.write_text(plan.model_dump_json(), encoding="utf-8")
    result = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "scripts/manage-daily-scan.ps1"),
        "-Action", "Preview", "-ConfigPath", str(config),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stderr
    preview = json.loads(result.stdout)
    assert preview["executable"].endswith("pythonw.exe")
    assert f'--config "{config}"' in preview["arguments"]
    assert preview["dailyAt"] == "09:00"


def test_partial_scan_consumes_daily_attempt_and_keeps_its_reason(tmp_path):
    from app.scheduling.service import run_due, history
    plan = plan_at(tmp_path)

    def partial(plan, db, run_id):
        result = fake_network_executor(plan, db, run_id)
        db.finish_job(result["jobId"], "partial", {}, "budget_exceeded")
        return result

    assert run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc),
                   executor=partial)["status"] == "partial"
    assert history(Database(plan.database))["items"][0]["error_code"] == "budget_exceeded"
    assert run_due(plan, now=datetime(2026, 11, 15, 2, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "already_attempted"


def test_recovery_does_not_relabel_already_finished_scan_as_interrupted(tmp_path):
    from app.scheduling.service import run_due, history
    from sqlalchemy import text
    plan = plan_at(tmp_path)
    run_due(plan, now=datetime(2026, 11, 15, 1, tzinfo=timezone.utc), executor=fake_network_executor)
    db = Database(plan.database)
    with db.engine.begin() as connection:
        connection.execute(text("UPDATE scheduled_scan_runs SET state='running', finished_at=NULL"))
    assert run_due(plan, now=datetime(2026, 11, 15, 2, tzinfo=timezone.utc),
                   executor=fake_network_executor)["status"] == "already_attempted"
    assert history(db)["items"][0]["state"] == "completed"
