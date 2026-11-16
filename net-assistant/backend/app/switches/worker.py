"""Automatic authorized-scope onboarding; hot config, fixed-code errors, no guessed secrets."""
import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import signal
import threading
import time

from app.discovery.store import initialize_database, scan_writer_lock
from app.discovery.types import utc_now
from app.runtime_files import write_atomic_json
from app.switches.config import credentials, load_switch_plan, readiness
from app.switches.snmp import SnmpFailure, collect_switch
from app.switches.store import SwitchStore


def identity(plan):
    return sha256((plan.model_dump_json() + plan.scan_config.read_text(encoding="utf-8-sig")).encode()).hexdigest()


def write_runtime(plan, value):
    plan.storage.mkdir(parents=True, exist_ok=True)
    write_atomic_json(plan.storage / "switch-state.json", value)


def read_runtime(plan):
    ready = readiness(plan)
    try:
        value = json.loads((plan.storage / "switch-state.json").read_text(encoding="utf-8"))
        if value.get("configIdentity") != identity(plan):
            raise ValueError("Changed configuration.")
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(value["heartbeatAt"])).total_seconds()
        if age < -60 or age > 90:
            return {**value, "state": "stale", "workerState": "stale",
                    "reasonCode": "switch_worker_heartbeat_stale"}
        return {**value, "workerState": (
            "running" if value["state"] in ("running", "collecting", "waiting_configuration", "disabled")
            else value["state"])}
    except (OSError, ValueError, TypeError, KeyError):
        return {**(ready if ready["state"] != "ready" else
                   {"state": "unknown", "reasonCode": "switch_worker_unavailable"}),
                "workerState": "unknown",
                "heartbeatAt": None, "lastCycle": None, "nextDueAt": None}


async def run_cycle(plan, db, *, collect=collect_switch, stop_event=None, progress=None):
    ready = readiness(plan)
    counts = {key: 0 for key in ("attempted", "completed", "partial", "failed", "ignored")}
    if ready["state"] != "ready":
        return {**ready, "counts": counts, "finishedAt": utc_now()}
    if db.readonly or db.path != plan.database:
        raise ValueError("Switch worker database mismatch.")
    store = SwitchStore(db)
    profiles = [(profile, credentials(profile)) for profile in plan.profiles]
    profiles = [(profile, secret) for profile, secret in profiles if secret is not None]
    scope_key = sha256(str(plan.scan_config).encode()).hexdigest()
    queue = asyncio.Queue()
    for address in plan.addresses():
        queue.put_nowait(address)

    async def inspect():
        while not queue.empty() and not (stop_event and stop_event.is_set()):
            address = queue.get_nowait()
            for profile, secret in profiles:
                if stop_event and stop_event.is_set():
                    break
                run_id = store.begin(address, profile.id, scope_key)
                counts["attempted"] += 1
                try:
                    sample = await asyncio.wait_for(
                        collect(address, profile, secret, plan), timeout=plan.target_budget_seconds + 10)
                    partial = any(item.get("state") in ("partial", "failed", "limited", "not_collected")
                                  for item in sample["capabilities"].values())
                    state = "partial" if partial else "completed"
                    store.finish(run_id, state, snapshot=sample)
                    counts[state] += 1
                    break
                except asyncio.CancelledError:
                    store.finish(run_id, "interrupted", error_code="switch_worker_stopped")
                    raise
                except (SnmpFailure, TimeoutError) as error:
                    code = error.code if isinstance(error, SnmpFailure) else "collection_budget_exceeded"
                    state = "ignored" if code == "not_ruijie_device" else "failed"
                    store.finish(run_id, state, error_code=code)
                    counts[state] += 1
                    if state == "ignored":
                        break
                except Exception:
                    store.finish(run_id, "failed", error_code="switch_collection_internal_error")
                    counts["failed"] += 1
                    break
                finally:
                    if progress:
                        progress(dict(counts))
            queue.task_done()

    # A storage failure must cancel and await every sibling, not leave background probes.
    async with asyncio.TaskGroup() as group:
        for _ in range(plan.concurrency):
            group.create_task(inspect())
    return {"state": "completed", "counts": counts, "finishedAt": utc_now(),
            "reasonCode": None}


async def _loop(path, plan, db, stop):
    value = {"state": "starting", "startedAt": utc_now(), "heartbeatAt": utc_now(),
             "lastCycle": None, "nextDueAt": None, "reasonCode": None}
    next_cycle, previous_identity = float("-inf"), None
    while not stop.is_set():
        try:
            loaded = load_switch_plan(path)
            if loaded.database != db.path or loaded.storage != plan.storage:
                raise ValueError("Hot configuration cannot change the database or storage owner.")
            digest = identity(loaded)
            if digest != previous_identity:
                next_cycle, previous_identity = float("-inf"), digest
            plan = loaded
            value["configIdentity"] = digest
            if time.monotonic() >= next_cycle:
                value.update(state="collecting", reasonCode=None, counts={})
                value["readyProfileCount"] = sum(credentials(profile) is not None for profile in plan.profiles)
                task = asyncio.create_task(run_cycle(
                    plan, db, stop_event=stop, progress=lambda counts: value.update(counts=counts)))
                try:
                    while not task.done():
                        if stop.is_set():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                            break
                        value["heartbeatAt"] = utc_now()
                        write_runtime(plan, value)
                        await asyncio.wait({task}, timeout=1)
                    if not task.cancelled() and not stop.is_set():
                        result = task.result()
                        value.update(
                            state="running" if result["state"] == "completed" else result["state"],
                            reasonCode=result["reasonCode"], lastCycle=result, counts=result["counts"])
                        delay = plan.interval_seconds if result["state"] == "completed" else 5
                        next_cycle = time.monotonic() + delay
                        value["nextDueAt"] = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()
                finally:
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
            value["heartbeatAt"] = utc_now()
            write_runtime(plan, value)
        except asyncio.CancelledError:
            raise
        except Exception:
            # No config text, usernames or exception messages enter runtime state.
            value.update(state="error", reasonCode="switch_configuration_or_storage_error",
                         heartbeatAt=utc_now(), nextDueAt=None)
            write_runtime(plan, value)
        for _ in range(5):
            if stop.is_set():
                break
            await asyncio.sleep(1)
    value.update(state="stopped", reasonCode="switch_worker_stopped", heartbeatAt=utc_now(), nextDueAt=None)
    write_runtime(plan, value)


def run_worker(path, *, stop_event=None, database=None):
    path = Path(path).resolve()
    plan = load_switch_plan(path)
    if database is not None and plan.database != Path(database).resolve():
        raise ValueError("Switch and automation databases must match.")
    stop = stop_event if stop_event is not None else threading.Event()
    if stop.is_set():
        return 0
    plan.storage.mkdir(parents=True, exist_ok=True)
    with scan_writer_lock(plan.storage / "switch.owner.sqlite"):
        db = initialize_database(plan.database)
        try:
            SwitchStore(db).interrupt()
            asyncio.run(_loop(path, plan, db, stop))
        finally:
            db.engine.dispose()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "status", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    plan = load_switch_plan(args.config)
    if args.command == "validate":
        print(json.dumps({**readiness(plan), "authorizedAddresses": len(plan.addresses()),
                          "networkRequests": 0}, ensure_ascii=False))
    elif args.command == "status":
        print(json.dumps(read_runtime(plan), ensure_ascii=False))
    else:
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        return run_worker(args.config, stop_event=stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
