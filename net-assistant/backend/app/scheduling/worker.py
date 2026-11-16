"""One scheduler owner; keep API workers independent and existing daily gate intact."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from app.discovery.config import ROOT, load_settings
from app.discovery.store import ScanBusyError, scan_writer_lock
from app.discovery.types import utc_now
from app.scheduling.config import load_plan
from app.scheduling.runtime import plan_identity, runtime_path, write_runtime


def _launch(plan_config, output):
    command = [sys.executable, str(ROOT / "scripts/service-bootstrap.py"),
               "due", "--config", str(plan_config)]
    handle = output.open("w", encoding="utf-8")
    try:
        child = subprocess.Popen(command, cwd=ROOT, stdout=handle, stderr=subprocess.DEVNULL,
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    except BaseException:
        handle.close()
        raise
    return child, handle


def run_worker(config, *, stop_event=None, stop_file=None, poll_seconds=30, launcher=None):
    if not .05 <= poll_seconds <= 3600:
        raise ValueError("poll_seconds must be between .05 and 3600.")
    plan = load_plan(config)
    settings = load_settings(plan.scan_config)
    if plan.enabled:
        from app.discovery.context import verified_source_network
        verified_source_network(settings.source_address)  # local adapter lookup, no probe packets
    identity = plan_identity(plan)
    stop = stop_event if stop_event is not None else threading.Event()
    owner_lock = runtime_path(plan).with_name(f"{plan.name}.owner.sqlite")
    try:
        with scan_writer_lock(owner_lock):
            return _owned_loop(plan, settings, identity, stop, stop_file, poll_seconds, launcher or _launch)
    except ScanBusyError:
        return 2


def _owned_loop(plan, settings, identity, stop, stop_file, poll_seconds, launch):
    from app.scheduling.windows_service import ChildJob
    state = {"instanceId": str(uuid4()), "startedAt": utc_now(), "state": "running",
             "heartbeatAt": utc_now(), "lastCheckedAt": None, "lastInvocation": None,
             "errorCode": None}
    child, output_handle = None, None
    last_check, child_started = float("-inf"), 0
    # Job Object makes a Windows worker crash kill the complete scan process tree.
    job_context = ChildJob() if os.name == "nt" else nullcontext()
    try:
        with job_context as job, tempfile.TemporaryDirectory(
                prefix=f"{plan.name}-", dir=runtime_path(plan).parent) as scratch:
            directory = Path(scratch)
            scan_snapshot = directory / "scan.json"
            scan_snapshot.write_text(settings.model_dump_json(), encoding="utf-8")
            frozen_plan = plan.model_copy(update={"scan_config": scan_snapshot})
            plan_snapshot = directory / "plan.json"
            plan_snapshot.write_text(frozen_plan.model_dump_json(), encoding="utf-8")
            output_path = directory / "result.json"
            while not stop.is_set() and not (stop_file and Path(stop_file).exists()):
                now = time.monotonic()
                if child is not None:
                    code = child.poll()
                    timed_out = code is None and now - child_started > settings.budget_seconds + 120
                    if timed_out:
                        if job:
                            job.terminate()
                        else:
                            child.kill()
                        child.wait(timeout=10)
                        code = child.returncode
                    if code is not None:
                        if output_handle:
                            output_handle.close()
                            output_handle = None
                        try:
                            value = json.loads(output_path.read_text(encoding="utf-8"))
                            status = value["status"]
                            if (code not in (0, 1, 2)
                                    or status not in ("disabled", "not_due", "already_attempted", "busy",
                                                      "completed", "partial", "failed", "interrupted")):
                                raise ValueError("Invalid invocation.")
                            state["lastInvocation"] = {
                                "status": status, "checkedAt": value.get("checkedAt", utc_now()),
                                "errorCode": None,
                            }
                        except (OSError, ValueError, KeyError, TypeError):
                            state["lastInvocation"] = {
                                "status": "invocation_failed", "checkedAt": utc_now(),
                                "errorCode": "schedule_invocation_failed",
                            }
                        if timed_out:
                            state["lastInvocation"] = {
                                "status": "timeout", "checkedAt": utc_now(),
                                "errorCode": "schedule_budget_exceeded",
                            }
                        child = None
                        last_check = now  # interval measured after completion, not scan start
                        state["state"] = "running"
                if child is None and now - last_check >= poll_seconds:
                    state["lastCheckedAt"] = utc_now()
                    if not plan.enabled:
                        state["lastInvocation"] = {"status": "disabled", "checkedAt": utc_now(),
                                                   "errorCode": None}
                        last_check = now
                    elif not plan.is_due():
                        state["lastInvocation"] = {"status": "not_due", "checkedAt": utc_now(),
                                                   "errorCode": None}
                        last_check = now
                    else:
                        child, output_handle = launch(plan_snapshot, output_path)
                        if job:
                            job.assign(child.pid)
                        child_started = now
                        # This means the gate is executing; database determines actual scan state.
                        state["state"] = "checking"
                state["heartbeatAt"] = utc_now()
                write_runtime(plan, state, identity=identity)
                stop.wait(min(2, poll_seconds))
            # Stop the child before publishing stopped and before deleting temporary files.
            if child is not None and child.poll() is None:
                if job:
                    job.terminate()
                else:
                    child.terminate()
                child.wait(timeout=10)
            if output_handle:
                output_handle.close()
                output_handle = None
            state.update(state="stopped", heartbeatAt=utc_now())
            write_runtime(plan, state, identity=identity)
        return 0
    except BaseException:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        if output_handle:
            output_handle.close()
        state.update(state="error", heartbeatAt=utc_now(), errorCode="scheduler_worker_failed")
        write_runtime(plan, state, identity=identity)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path)
    parser.add_argument("--poll-seconds", type=float, default=30)
    args = parser.parse_args(argv)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        return run_worker(args.config, stop_event=stop, stop_file=args.stop_file,
                          poll_seconds=args.poll_seconds)
    except Exception as error:
        print(json.dumps({"code": "scheduler_worker_failed", "errorType": type(error).__name__}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
