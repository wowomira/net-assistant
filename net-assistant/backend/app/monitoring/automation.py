"""One owned Gatus process plus periodic local snapshots; no implicit remote scans."""
import argparse
import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import signal
import threading
import time
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.collectors.store import NetworkStore
from app.discovery.config import ROOT
from app.discovery.store import initialize_database, scan_writer_lock
from app.discovery.types import utc_now
from app.runtime_files import write_atomic_json
from app.monitoring.config import load_plan, render_gatus
from app.monitoring.client import GatusClient, GatusError
from app.monitoring.runtime import run_gatus
from app.runtime_tools import gatus_executable


class AutomationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: UUID
    device_label: str = Field(min_length=1, max_length=120)
    asset_id: UUID | None = None
    database: Path
    monitoring_plan: Path
    storage: Path
    switch_plan: Path | None = None
    collector_interval_seconds: int = Field(default=300, ge=30, le=86400)

    @field_validator("database", "monitoring_plan", "storage", "switch_plan")
    @classmethod
    def absolute(cls, path):
        if path is None:
            return None
        if not path.is_absolute():
            raise ValueError("Automation paths must be absolute after loading.")
        return path.resolve()


def load_automation(path):
    path = Path(path).resolve()
    values = json.loads(path.read_text(encoding="utf-8-sig"))
    for field in ("database", "monitoring_plan", "storage", "switch_plan"):
        if field in values and values[field] is not None:
            values[field] = str((path.parent / values[field]).resolve())
    return AutomationPlan.model_validate(values)


def identity(plan):
    # Include the monitoring file contents: old heartbeat cannot validate an edited plan.
    value = plan.model_dump_json() + plan.monitoring_plan.read_text(encoding="utf-8-sig")
    return sha256(value.encode()).hexdigest()


def state_path(plan):
    return plan.storage.parent / "automation-state.json"


def write_state(plan, state):
    write_atomic_json(state_path(plan), state, indent=2)


def read_state(plan):
    try:
        state = json.loads(state_path(plan).read_text(encoding="utf-8"))
        if state.get("configIdentity") != identity(plan):
            return {"state": "unknown", "errorCode": "automation_config_changed"}
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(state["heartbeatAt"])).total_seconds()
        if age < -60:
            return {"state": "unknown", "errorCode": "automation_clock_invalid"}
        if state["state"] == "running" and age > 90:
            return {**state, "state": "stale", "gatusReady": False,
                    "errorCode": "automation_heartbeat_stale"}
        return state
    except (OSError, ValueError, KeyError, TypeError):
        return {"state": "unknown", "errorCode": "automation_state_unavailable"}


def validate_automation(config):
    plan = load_automation(config)
    monitor = load_plan(plan.monitoring_plan)
    from urllib.parse import urlsplit
    render_gatus(monitor, plan.storage, urlsplit(monitor.api_url).port)
    if plan.storage == plan.database:
        raise ValueError("Monitoring and inspection databases must be separate.")
    if plan.switch_plan is not None:
        from app.switches.config import load_switch_plan
        if load_switch_plan(plan.switch_plan).database != plan.database:
            raise ValueError("Switch and automation databases must match.")
    if not gatus_executable(ROOT).is_file():
        raise FileNotFoundError("Project-local Gatus is missing.")
    return plan, monitor


def run_automation(config, *, stop_event=None):
    plan, monitor = validate_automation(config)
    stop = stop_event if stop_event is not None else threading.Event()
    if stop.is_set():
        return 0
    plan.storage.parent.mkdir(parents=True, exist_ok=True)
    with scan_writer_lock(plan.storage.parent / "automation.owner.sqlite"):
        return _run_owned(plan, monitor, stop)


def _run_owned(plan, monitor, stop):
    # initialize_database performs a validated consistent backup before migration.
    db = initialize_database(plan.database)
    store = NetworkStore(db)
    state = {"state": "starting", "startedAt": utc_now(), "heartbeatAt": utc_now(),
             "deviceId": str(plan.device_id), "configIdentity": identity(plan),
             "lastCollection": None, "collectorErrorCode": None, "errorCode": None,
             "gatusReady": False, "gatusErrorCode": None}
    last_collection, last_gatus_check = float("-inf"), float("-inf")
    switch_stop, switch_thread = threading.Event(), None
    if plan.switch_plan is not None:
        def run_switches():
            from app.switches.worker import run_worker
            while not switch_stop.is_set():
                try:
                    state["switchWorkerErrorCode"] = None
                    run_worker(plan.switch_plan, stop_event=switch_stop, database=plan.database)
                except Exception:
                    state["switchWorkerErrorCode"] = "switch_worker_failed"
                if switch_stop.wait(10):
                    break
        switch_thread = threading.Thread(target=run_switches, name="switch-collector", daemon=True)
        switch_thread.start()

    def tick(process):
        nonlocal last_collection, last_gatus_check
        now = time.monotonic()
        if now - last_collection >= plan.collector_interval_seconds:
            try:
                result = store.collect(plan.device_id, plan.device_label, asset_id=plan.asset_id)
                state["lastCollection"] = {key: result[key] for key in (
                    "id", "state", "observedAt", "finishedAt", "errorCode")}
                state["collectorErrorCode"] = result["errorCode"]
            except Exception as error:
                # Storage or mapping failure is NOT a successful empty collection.
                state["collectorErrorCode"] = "network_collection_storage_or_mapping_failed"
                state["lastCollection"] = {"state": "failed", "finishedAt": utc_now(),
                                          "errorCode": state["collectorErrorCode"],
                                          "errorType": type(error).__name__}
            last_collection = time.monotonic()
        if now - last_gatus_check >= 10 or not state["gatusReady"]:
            try:
                statuses = asyncio.run(GatusClient(monitor).statuses())
                state["gatusReady"] = bool(statuses["items"]) and all(
                    item["status"] in ("up", "down", "stale") for item in statuses["items"])
                state["gatusErrorCode"] = None if state["gatusReady"] else "gatus_samples_pending"
            except GatusError as error:
                state["gatusReady"], state["gatusErrorCode"] = False, str(error)
            last_gatus_check = time.monotonic()
        state.update(state="running", heartbeatAt=utc_now(), gatusProcessId=process.pid)
        state["switchWorkerAlive"] = bool(switch_thread and switch_thread.is_alive())
        write_state(plan, state)

    try:
        code = run_gatus(monitor, gatus_executable(ROOT), plan.storage,
                         stop_event=stop, tick=tick)
        state.update(state="stopped" if stop.is_set() else "error", heartbeatAt=utc_now(),
                     gatusReady=False, errorCode=None if stop.is_set() else "gatus_process_exited")
        write_state(plan, state)
        return 0 if stop.is_set() else code or 1
    except Exception:
        state.update(state="error", heartbeatAt=utc_now(), gatusReady=False,
                     errorCode="monitoring_automation_failed")
        write_state(plan, state)
        raise
    finally:
        switch_stop.set()
        if switch_thread:
            switch_thread.join(timeout=15)
        db.engine.dispose()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "status", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "validate":
        plan, monitor = validate_automation(args.config)
        print(json.dumps({"plan": plan.model_dump(mode="json"), "endpoints": len(monitor.endpoints),
                          "networkRequests": 0}, ensure_ascii=False))
    elif args.command == "status":
        print(json.dumps(read_state(load_automation(args.config)), ensure_ascii=False))
    else:
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        return run_automation(args.config, stop_event=stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
