"""Read-only schedule/result queries. Never migrate, recover, or trigger a scan."""
from datetime import timedelta

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.discovery.config import ROOT
from app.discovery.models import JobRow
from app.discovery.store import Database
from app.scheduling.models import ScheduledRunRow
from app.scheduling.runtime import read_runtime


RUN_FIELDS = ("id", "schedule_name", "local_date", "state", "started_at", "finished_at", "error_code")


def run_view(session, row):
    if row is None:
        return None
    job_id = session.scalar(select(JobRow.id).where(
        JobRow.schedule_run_id == row.id).order_by(JobRow.sequence.desc()).limit(1))
    return {**{key: getattr(row, key) for key in RUN_FIELDS}, "job_id": job_id}


def require_schema(session):
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    expected = set(ScriptDirectory.from_config(config).get_heads())
    actual = set(session.scalars(text("SELECT version_num FROM alembic_version")))
    if actual != expected:
        raise ValueError("Unsupported schema.")


def recent_runs(plan, *, limit=50, cursor=None):
    if not plan.database.is_file():
        return {"items": [], "next_cursor": None}
    db = Database(plan.database, readonly=True)
    with Session(db.engine) as session, session.begin():
        session.connection().exec_driver_sql("BEGIN")  # sqlite legacy mode does not BEGIN on SELECT
        require_schema(session)
        query = select(ScheduledRunRow).where(ScheduledRunRow.schedule_name == plan.name)
        return db._page(session, query, ScheduledRunRow, lambda row: run_view(session, row), limit, cursor)


def schedule_status(plan, *, now=None):
    local = plan.local_now(now)
    today = local.date().isoformat()
    latest, today_run = None, None
    database = {"state": "missing", "reasonCode": "database_missing"}
    if plan.database.is_file():
        try:
            db = Database(plan.database, readonly=True)
            # One read snapshot for today's record and latest record.
            with Session(db.engine) as session, session.begin():
                session.connection().exec_driver_sql("BEGIN")
                require_schema(session)
                latest = run_view(session, session.scalar(select(ScheduledRunRow).where(
                    ScheduledRunRow.schedule_name == plan.name
                ).order_by(ScheduledRunRow.sequence.desc()).limit(1)))
                today_run = run_view(session, session.scalar(select(ScheduledRunRow).where(
                    ScheduledRunRow.schedule_name == plan.name, ScheduledRunRow.local_date == today)))
            database = {"state": "available", "reasonCode": None}
        except (SQLAlchemyError, ValueError, OSError):
            latest, today_run = None, None
            database = {"state": "unavailable", "reasonCode": "database_unavailable"}
    worker = read_runtime(plan, now=now)
    if database["state"] == "unavailable":
        today_status = "unknown"
    elif not plan.enabled:
        today_status = "disabled"
    elif today_run:
        today_status = (today_run["state"] if today_run["state"] != "running"
                        or worker["state"] == "checking" else "unknown")
    else:
        today_status = "pending" if plan.is_due(local) else "not_due"
    nominal = local.replace(hour=int(plan.at[:2]), minute=int(plan.at[3:]), second=0, microsecond=0)
    if today_run:
        nominal += timedelta(days=1)
    return {
        "configured": True,
        "schedule": {
            "name": plan.name, "enabled": plan.enabled, "dailyAt": plan.at,
            "utcOffsetMinutes": plan.utc_offset_minutes, "localDate": today,
            "nextDueAt": nominal.isoformat() if plan.enabled else None,
        },
        "worker": worker, "database": database,
        "todayStatus": today_status, "latestRun": latest, "todayRun": today_run,
    }
