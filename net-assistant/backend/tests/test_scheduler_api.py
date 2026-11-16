"""Read-only contracts; synthetic heartbeats are evidence for tests only."""
from datetime import datetime, timedelta, timezone
import asyncio
import json

import httpx
from sqlalchemy.orm import Session

from app.main import create_app
from app.discovery.store import initialize_database
from app.scheduling.models import ScheduledRunRow
from app.scheduling.runtime import write_runtime
from test_scheduler_runtime import make_plan


class ApiClient:
    """Use the existing HTTPX ASGI transport, without a deprecated TestClient adapter."""
    def __init__(self, app):
        self.app = app

    def request(self, method, path):
        async def perform():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                         base_url="http://testserver") as client:
                return await client.request(method, path)
        return asyncio.run(perform())

    def get(self, path):
        return self.request("GET", path)

    def post(self, path):
        return self.request("POST", path)


def client_for(plan, config):
    return ApiClient(create_app(allow_anonymous_reads=True, database_path=plan.database, schedule_config_path=config))


def test_scheduler_endpoint_exists_without_implicitly_creating_a_database(tmp_path):
    client = ApiClient(create_app(allow_anonymous_reads=True, database_path=tmp_path / "missing.sqlite"))
    response = client.get("/api/v1/scheduler")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["worker"]["state"] == "unknown"
    assert body["todayStatus"] == "unconfigured"
    assert not (tmp_path / "missing.sqlite").exists()


def test_missing_heartbeat_never_claims_worker_alive_or_scan_success(tmp_path):
    plan, config = make_plan(tmp_path, enabled=True)
    body = client_for(plan, config).get("/api/v1/scheduler").json()
    assert body["configured"] is True
    assert body["worker"]["state"] == "unknown"
    assert body["database"]["state"] == "missing"
    assert body["todayStatus"] == "pending"
    assert body["latestRun"] is None
    assert body["capabilities"]["hostMetrics"] is False
    assert body["capabilities"]["verifiedHostIdentity"] is False
    assert body["capabilities"]["manualScanEntry"] == "local_cli"
    assert str(tmp_path) not in json.dumps(body, ensure_ascii=False)
    assert not plan.database.exists()
    assert not (tmp_path / "runtime").exists()


def test_recent_heartbeat_is_distinct_from_last_failed_scan(tmp_path):
    plan, config = make_plan(tmp_path, enabled=True)
    db = initialize_database(plan.database)
    now = datetime.now(timezone.utc)
    date = plan.local_now(now).date().isoformat()
    with Session(db.engine) as session, session.begin():
        session.add(ScheduledRunRow(
            id="test-failed-run", schedule_name=plan.name, local_date=date, state="failed",
            started_at=now.isoformat(), finished_at=now.isoformat(),
            error_code="scan_execution_failed", config_snapshot=plan.model_dump(mode="json"),
        ))
    write_runtime(plan, {
        "instanceId": "synthetic", "state": "running", "heartbeatAt": now.isoformat(),
        "lastInvocation": {"status": "already_attempted", "checkedAt": now.isoformat()},
    })
    client = client_for(plan, config)
    response = client.get("/api/v1/scheduler")
    body = response.json()
    assert body["worker"]["state"] == "running"
    assert body["todayStatus"] == "failed"
    assert body["latestRun"]["errorCode"] == "scan_execution_failed"
    assert body["latestRun"]["jobId"] is None
    assert body["worker"]["lastInvocation"]["status"] == "already_attempted"
    assert response.headers["cache-control"] == "no-store"
    page = client.get("/api/v1/scheduler/runs").json()
    assert len(page["items"]) == 1 and page["items"][0]["state"] == "failed"
    assert "configSnapshot" not in page["items"][0]
    assert str(tmp_path) not in json.dumps(body, ensure_ascii=False)


def test_stale_and_changed_configuration_never_get_a_green_worker(tmp_path):
    plan, config = make_plan(tmp_path)
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    write_runtime(plan, {"instanceId": "test", "state": "running", "heartbeatAt": old.isoformat()})
    client = client_for(plan, config)
    assert client.get("/api/v1/scheduler").json()["worker"]["state"] == "stale"
    plan.at = "10:30"
    config.write_text(plan.model_dump_json(), encoding="utf-8")
    body = client.get("/api/v1/scheduler").json()
    assert body["worker"]["state"] == "unknown"
    assert body["worker"]["reasonCode"] == "configuration_changed"


def test_wrong_database_invalid_config_and_history_parameters_are_rejected(tmp_path):
    plan, config = make_plan(tmp_path)
    client = ApiClient(create_app(allow_anonymous_reads=True, database_path=tmp_path / "other.sqlite",
                                   schedule_config_path=config))
    result = client.get("/api/v1/scheduler")
    assert result.status_code == 503
    assert result.json()["code"] == "scheduler_configuration_invalid"
    assert str(tmp_path) not in result.text
    client = client_for(plan, config)
    assert client.get("/api/v1/scheduler/runs?limit=201").status_code == 422
    assert client.get("/api/v1/scheduler/runs?cursor=-1").status_code == 422
    config.write_text("{broken", encoding="utf-8")
    assert client.get("/api/v1/scheduler").status_code == 503


def test_endpoints_are_read_only_and_empty_history_creates_nothing(tmp_path):
    plan, config = make_plan(tmp_path)
    client = client_for(plan, config)
    assert client.get("/api/v1/scheduler/runs").json() == {"items": [], "nextCursor": None}
    assert client.post("/api/v1/scheduler").status_code == 401
    assert client.post("/api/v1/scheduler/runs").status_code == 401
    assert client.get("/api/progress").status_code == 404
    schema = client.get("/openapi.json").json()
    assert schema["paths"]["/api/v1/scheduler"]["get"]["operationId"] == "getSchedulerStatus"
    assert not plan.database.exists()


def test_unrelated_or_old_database_reports_unavailable_without_migration(tmp_path):
    import sqlite3
    plan, config = make_plan(tmp_path)
    with sqlite3.connect(plan.database) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('do not touch')")
    before = plan.database.read_bytes()
    response = client_for(plan, config).get("/api/v1/scheduler")
    assert response.status_code == 200
    assert response.json()["database"]["state"] == "unavailable"
    assert response.json()["todayStatus"] == "unknown"
    assert plan.database.read_bytes() == before
    assert client_for(plan, config).get("/api/v1/scheduler/runs").status_code == 503


def test_abandoned_running_record_is_not_claimed_as_live_work(tmp_path):
    plan, config = make_plan(tmp_path, enabled=True)
    db = initialize_database(plan.database)
    now = datetime.now(timezone.utc)
    with Session(db.engine) as session, session.begin():
        session.add(ScheduledRunRow(
            id="abandoned", schedule_name=plan.name, local_date=plan.local_now().date().isoformat(),
            state="running", started_at=now.isoformat(), finished_at=None,
            error_code=None, config_snapshot={},
        ))
    body = client_for(plan, config).get("/api/v1/scheduler").json()
    assert body["todayStatus"] == "unknown"
    assert body["todayRun"]["state"] == "running"
    write_runtime(plan, {"instanceId": "idle-worker", "state": "running",
                         "heartbeatAt": now.isoformat()})
    # A live but idle scheduler is not evidence that an abandoned scan is executing.
    assert client_for(plan, config).get("/api/v1/scheduler").json()["todayStatus"] == "unknown"
    with Session(db.engine) as session:
        assert session.query(ScheduledRunRow).one().state == "running"  # GET must not recover/write


def test_status_really_starts_a_sqlite_read_snapshot(tmp_path, monkeypatch):
    from sqlalchemy import event
    from app.discovery.store import Database
    from app.scheduling import status
    plan, _ = make_plan(tmp_path)
    initialize_database(plan.database)
    traces = []
    original = Database

    def traced(*args, **kwargs):
        db = original(*args, **kwargs)

        @event.listens_for(db.engine, "connect")
        def collect(connection, _):
            connection.set_trace_callback(traces.append)
        return db

    monkeypatch.setattr(status, "Database", traced)
    status.schedule_status(plan)
    assert any(statement.strip().upper() == "BEGIN" for statement in traces)
