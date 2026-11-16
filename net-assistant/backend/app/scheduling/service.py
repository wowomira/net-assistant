"""Persistent once-per-local-day gate. The OS wakes this code; HTTP never does."""
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.discovery.config import load_settings
from app.discovery.models import JobRow
from app.discovery.store import ScanBusyError, initialize_database, scan_writer_lock
from app.discovery.types import utc_now
from app.scheduling.models import ScheduledRunRow


def _view(session, row):
    job_id = session.scalar(select(JobRow.id).where(
        JobRow.schedule_run_id == row.id).order_by(JobRow.sequence.desc()).limit(1))
    return {**{key: getattr(row, key) for key in (
        "id", "schedule_name", "local_date", "state", "started_at",
        "finished_at", "error_code", "config_snapshot",
    )}, "job_id": job_id}


def history(db, limit=50, cursor=None, schedule_name=None):
    statement = select(ScheduledRunRow)
    if schedule_name:
        statement = statement.where(ScheduledRunRow.schedule_name == schedule_name)
    with Session(db.engine) as session:
        return db._page(session, statement, ScheduledRunRow,
                        lambda row: _view(session, row), limit, cursor)


def _recover(db):
    """Only while owning the process lock: previous 'running' cannot be live."""
    db.interrupt_stale_jobs()
    with Session(db.engine) as session, session.begin():
        for row in session.scalars(select(ScheduledRunRow).where(ScheduledRunRow.state == "running")):
            job = session.scalar(select(JobRow).where(
                JobRow.schedule_run_id == row.id).order_by(JobRow.sequence.desc()).limit(1))
            row.state = job.state if job and job.state != "running" else "interrupted"
            row.error_code = job.error_code if job else "previous_process_interrupted"
            row.finished_at = utc_now()


def _default_executor(plan, db, run_id):
    from app.discovery.execution import execute_scan
    return execute_scan(load_settings(plan.scan_config), db, plan.report_directory,
                        trigger="scheduled", schedule_run_id=run_id)


def _due_locked(plan, db, local_date, executor):
    _recover(db)
    with Session(db.engine) as session, session.begin():
        old = session.scalar(select(ScheduledRunRow).where(
            ScheduledRunRow.schedule_name == plan.name, ScheduledRunRow.local_date == local_date))
        if old:
            return {"status": "already_attempted", "localDate": local_date, "run": _view(session, old)}
        run_id = str(uuid4())
        session.add(ScheduledRunRow(
            id=run_id, schedule_name=plan.name, local_date=local_date,
            state="running", started_at=utc_now(), finished_at=None,
            error_code=None, config_snapshot=plan.model_dump(mode="json"),
        ))
    try:
        output = executor(plan, db, run_id)
        job = db.get_job(output["jobId"])
        if not job or job["schedule_run_id"] != run_id or job["state"] == "running":
            raise ValueError("Executor did not return a finished job for this scheduled run.")
        state, error = job["state"], job["error_code"]
    except Exception as exception:
        # Do not copy arbitrary exception messages (may contain environment secrets).
        state, error = "failed", "scan_execution_failed"
        output = {"errorType": type(exception).__name__}
    except BaseException:
        with Session(db.engine) as session, session.begin():
            row = session.scalar(select(ScheduledRunRow).where(ScheduledRunRow.id == run_id))
            row.state, row.error_code, row.finished_at = "interrupted", "scan_interrupted", utc_now()
        raise
    with Session(db.engine) as session, session.begin():
        row = session.scalar(select(ScheduledRunRow).where(ScheduledRunRow.id == run_id))
        row.state, row.error_code, row.finished_at = state, error, utc_now()
    return {"status": state, "localDate": local_date, "runId": run_id, **output}


def run_due(plan, *, now=None, executor=None):
    local = plan.local_now(now)
    if not plan.enabled:
        return {"status": "disabled"}
    if not plan.is_due(local):
        return {"status": "not_due", "localDate": local.date().isoformat(), "at": plan.at}
    # Busy means no daily slot claimed. The OS may retry this invocation later.
    try:
        with scan_writer_lock(plan.database):
            return _due_locked(plan, initialize_database(plan.database),
                               local.date().isoformat(), executor or _default_executor)
    except ScanBusyError:
        return {"status": "busy", "localDate": local.date().isoformat()}
