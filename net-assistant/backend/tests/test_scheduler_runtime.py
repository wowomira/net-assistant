"""Independent files and real child processes; no production scans."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from app.discovery.config import ROOT
from app.scheduling.config import DailyPlan


def make_plan(tmp_path, *, enabled=False):
    scan = tmp_path / "scope.json"
    scan.write_text(json.dumps({"name": "runtime-test", "targets": ["10.17.0.10"], "ports": [80]}),
                    encoding="utf-8")
    plan = DailyPlan(name="runtime-test", enabled=enabled, at="00:00", scan_config=scan,
                     database=tmp_path / "test.sqlite", report_directory=tmp_path / "reports")
    config = tmp_path / "daily.json"
    config.write_text(plan.model_dump_json(), encoding="utf-8")
    return plan, config


def test_runtime_module_is_available():
    from importlib.util import find_spec
    assert find_spec("app.scheduling.runtime") is not None


def test_http_acceptance_tool_has_explicit_scheduler_mode():
    result = subprocess.run([sys.executable, "scripts/smoke_test.py", "--help"],
                            cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0
    assert "--scheduler" in result.stdout


def test_heartbeat_fresh_stale_wrong_database_and_corrupt_are_not_green(tmp_path):
    from app.scheduling.runtime import read_runtime, write_runtime, runtime_path
    plan, _ = make_plan(tmp_path)
    now = datetime(2026, 11, 15, 1, tzinfo=timezone.utc)
    assert read_runtime(plan, now=now)["state"] == "unknown"
    write_runtime(plan, {"instanceId": "test", "state": "running", "heartbeatAt": now.isoformat()})
    assert read_runtime(plan, now=now)["state"] == "running"
    assert read_runtime(plan, now=now + timedelta(seconds=91))["state"] == "stale"
    assert read_runtime(plan, now=now - timedelta(minutes=1))["state"] == "unknown"
    another = plan.model_copy(update={"database": tmp_path / "other.sqlite"})
    runtime_path(another).parent.mkdir(parents=True, exist_ok=True)
    runtime_path(another).write_text(runtime_path(plan).read_text(), encoding="utf-8")
    assert read_runtime(another, now=now)["state"] == "unknown"
    runtime_path(plan).write_text("{broken", encoding="utf-8")
    assert read_runtime(plan, now=now)["state"] == "unknown"
    assert not plan.database.exists()


def test_disabled_worker_real_process_heartbeat_stop_and_no_database(tmp_path):
    from app.scheduling.runtime import read_runtime
    plan, config = make_plan(tmp_path)
    stop = tmp_path / "stop"
    command = [sys.executable, "-m", "app.scheduling.worker", "--config", str(config),
               "--stop-file", str(stop), "--poll-seconds", "0.2"]
    child = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and read_runtime(plan)["state"] != "running":
            if child.poll() is not None:
                pytest.fail(child.communicate()[1].decode(errors="replace"))
            time.sleep(.1)
        assert read_runtime(plan)["state"] == "running"
        duplicate = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=15)
        assert duplicate.returncode == 2
        assert read_runtime(plan)["state"] == "running"  # duplicate must not overwrite owner
        stop.touch()
        assert child.wait(timeout=15) == 0
        assert read_runtime(plan)["state"] == "stopped"
        assert not plan.database.exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


def test_worker_stops_active_child_without_waiting_full_scan_budget(tmp_path):
    from app.scheduling.worker import run_worker
    from app.scheduling.runtime import read_runtime
    plan, config = make_plan(tmp_path, enabled=True)
    stop = threading.Event()
    children = []

    def launch(*_):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"])
        children.append(process)
        stop.set()
        return process, None

    assert run_worker(config, stop_event=stop, poll_seconds=.05, launcher=launch) == 0
    assert children and children[0].poll() is not None
    assert read_runtime(plan)["state"] == "stopped"
    assert not plan.database.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object")
def test_worker_crash_kills_scan_child_instead_of_leaving_an_orphan(tmp_path):
    import ctypes
    from ctypes import wintypes
    from app.scheduling.runtime import read_runtime
    plan, config = make_plan(tmp_path, enabled=True)
    pid_path = tmp_path / "scan-pid"
    script = (
        "import subprocess,sys; from pathlib import Path; "
        "from app.scheduling.worker import run_worker\n"
        "def launch(*args):\n"
        " p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(90)'])\n"
        " Path(sys.argv[2]).write_text(str(p.pid))\n"
        " return p,None\n"
        "run_worker(Path(sys.argv[1]),launcher=launch,poll_seconds=.1)\n"
    )
    worker = subprocess.Popen([sys.executable, "-c", script, str(config), str(pid_path)], cwd=ROOT)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = None
    try:
        deadline = time.monotonic() + 15
        while read_runtime(plan)["state"] != "checking" and time.monotonic() < deadline:
            assert worker.poll() is None
            time.sleep(.1)
        assert read_runtime(plan)["state"] == "checking"
        handle = kernel.OpenProcess(0x100000, False, int(pid_path.read_text()))
        assert handle
        worker.kill()
        worker.wait(timeout=10)
        assert kernel.WaitForSingleObject(handle, 10000) == 0
        assert not plan.database.exists()
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=10)
        if handle:
            kernel.CloseHandle(handle)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native service")
def test_service_preview_is_portable_low_privilege_and_does_not_install(tmp_path):
    # The checkout must not depend on the author's ignored live plan.
    _, config = make_plan(tmp_path)
    result = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "scripts/manage-discovery-service.ps1"), "-Action", "Preview",
        "-ConfigPath", str(config),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["account"] == r"NT SERVICE\NetAssistant-Discovery"
    assert data["requiresUserLogin"] is False
    assert data["startup"] == "Automatic"
    assert str(ROOT) in data["command"]
    assert "service-bootstrap.py" in data["command"]
    assert data["configValidated"] is True
    assert data["registrationMethod"] == "Win32_Service.Create"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows service status")
def test_service_management_status_does_not_depend_on_a_readable_plan(tmp_path):
    result = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "scripts/manage-discovery-service.ps1"), "-Action", "Status",
        "-ServiceName", "NetAssistant-Uninstalled-Test",
        "-ConfigPath", str(tmp_path / "missing.json"),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["installed"] is False
    assert not (tmp_path / "missing.json").exists()
