from importlib.util import find_spec
import json
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest

from app.discovery.config import ROOT


def test_automation_module_exists():
    assert find_spec("app.monitoring.automation") is not None


def test_automation_config_requires_stable_device_and_absolute_resolved_paths(tmp_path):
    from app.monitoring.automation import load_automation
    config = tmp_path / "automation.json"
    config.write_text(json.dumps({
        "device_id": str(uuid4()), "device_label": "test-only local host",
        "database": "test.sqlite", "monitoring_plan": "monitoring.json",
        "storage": "gatus.sqlite", "collector_interval_seconds": 300,
    }), encoding="utf-8")
    plan = load_automation(config)
    assert plan.database == tmp_path / "test.sqlite"
    assert plan.monitoring_plan == tmp_path / "monitoring.json"
    assert not plan.database.exists()
    values = json.loads(config.read_text(encoding="utf-8"))
    values["device_id"] = "not-a-uuid"
    config.write_text(json.dumps(values), encoding="utf-8")
    with pytest.raises(ValueError):
        load_automation(config)


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows service script")
@pytest.mark.skipif(not (ROOT / "tools/gatus/bin/gatus.exe").is_file()
                   and not (ROOT.parents[1] / ".runtime/tools/gatus/gatus.exe").is_file(),
                    reason="Service preview validates an explicitly installed Gatus binary")
def test_monitoring_service_preview_does_not_install_or_collect(tmp_path):
    config = tmp_path / "automation.json"
    monitor = tmp_path / "monitoring.json"
    monitor.write_text(json.dumps({
        "allowed_hosts": ["127.0.0.1"], "allow_loopback": True,
        "endpoints": [{"id": "test-only", "url": "tcp://127.0.0.1:65530"}],
    }), encoding="utf-8")
    config.write_text(json.dumps({
        "device_id": str(uuid4()), "device_label": "test-only",
        "database": str(tmp_path / "test.sqlite"), "monitoring_plan": str(monitor),
        "storage": str(tmp_path / "gatus.sqlite"),
    }), encoding="utf-8")
    # Preview validates without project-path deployment checks; Install enforces them.
    result = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "scripts/manage-monitoring-service.ps1"),
        "-Action", "Preview", "-ConfigPath", str(config),
        "-ServiceName", "NetAssistant-Monitoring-Test",
    ], capture_output=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stderr
    preview = json.loads(result.stdout)
    assert preview["account"] == r"NT SERVICE\NetAssistant-Monitoring-Test"
    assert preview["startup"] == "Automatic"
    assert preview["requiresUserLogin"] is False
    assert preview["endpoints"] == 1
    assert not (tmp_path / "test.sqlite").exists()
    assert not (tmp_path / "gatus.sqlite").exists()


def make_automation(tmp_path, monkeypatch):
    # These are state-machine tests with a mocked process. Keep their filesystem
    # prerequisite explicitly synthetic and local, not the author's real binary.
    executable = tmp_path / "tools/gatus/bin/gatus.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test-only-placeholder-not-an-executable")
    monkeypatch.setattr("app.monitoring.automation.ROOT", tmp_path)
    monitoring = tmp_path / "monitoring.json"
    monitoring.write_text(json.dumps({
        "allowed_hosts": ["127.0.0.1"], "allow_loopback": True,
        "endpoints": [{"id": "test-only", "url": "tcp://127.0.0.1:65530"}],
    }), encoding="utf-8")
    config = tmp_path / "automation.json"
    config.write_text(json.dumps({
        "device_id": str(uuid4()), "device_label": "test-only",
        "database": "test.sqlite", "monitoring_plan": "monitoring.json",
        "storage": "gatus.sqlite",
    }), encoding="utf-8")
    return config


def test_duplicate_automation_does_not_overwrite_owner_or_initialize_database(tmp_path, monkeypatch):
    from app.discovery.store import ScanBusyError, scan_writer_lock
    from app.monitoring.automation import load_automation, run_automation, state_path
    config = make_automation(tmp_path, monkeypatch)
    plan = load_automation(config)
    state_path(plan).write_text('{"owner":"test-only-active-owner"}', encoding="utf-8")
    def forbidden_initialization(*_):
        pytest.fail("A duplicate must reject ownership before initializing any database.")
    monkeypatch.setattr("app.monitoring.automation.initialize_database", forbidden_initialization)
    with scan_writer_lock(plan.storage.parent / "automation.owner.sqlite"):
        with pytest.raises(ScanBusyError):
            run_automation(config)
    assert state_path(plan).read_text(encoding="utf-8") == '{"owner":"test-only-active-owner"}'
    assert not plan.database.exists()


def test_automation_tick_persists_snapshot_and_stop_state(tmp_path, monkeypatch):
    import threading
    from types import SimpleNamespace
    from app.collectors.contracts import NetworkSnapshot
    from app.collectors.store import NetworkStore
    from app.discovery.store import Database
    from app.discovery.types import utc_now
    from app.monitoring.automation import load_automation, read_state, run_automation
    config = make_automation(tmp_path, monkeypatch)
    plan = load_automation(config)
    stop = threading.Event()
    monkeypatch.setattr("app.collectors.windows.collect_network", lambda: NetworkSnapshot(
        source="windows_native", observed_at=utc_now(), interfaces=[], neighbors=[]))
    async def ready_status(_self):
        return {"status": "available", "items": [{"status": "up"}]}
    monkeypatch.setattr("app.monitoring.client.GatusClient.statuses", ready_status)

    def run_test_process(_plan, _exe, _storage, *, stop_event, tick):
        tick(SimpleNamespace(pid=12345))
        assert read_state(plan)["lastCollection"]["state"] == "completed"
        assert read_state(plan)["state"] == "running"
        assert read_state(plan)["gatusReady"] is True
        stop_event.set()
        return 0

    monkeypatch.setattr("app.monitoring.automation.run_gatus", run_test_process)
    assert run_automation(config, stop_event=stop) == 0
    assert read_state(plan)["state"] == "stopped"
    assert read_state(plan)["gatusReady"] is False
    latest = NetworkStore(Database(plan.database, readonly=True)).latest(str(plan.device_id))
    assert latest["state"] == "completed"
    assert latest["snapshot"]["interfaces"] == []


def test_automation_does_not_claim_gatus_ready_when_upstream_is_missing(tmp_path, monkeypatch):
    import threading
    from types import SimpleNamespace
    from app.collectors.contracts import NetworkSnapshot
    from app.discovery.types import utc_now
    from app.monitoring.automation import load_automation, read_state, run_automation
    from app.monitoring.client import GatusError
    config = make_automation(tmp_path, monkeypatch)
    plan, stop = load_automation(config), threading.Event()
    monkeypatch.setattr("app.collectors.windows.collect_network", lambda: NetworkSnapshot(
        source="windows_native", observed_at=utc_now(), interfaces=[], neighbors=[]))

    async def unavailable(_self):
        raise GatusError("gatus_unavailable")

    monkeypatch.setattr("app.monitoring.client.GatusClient.statuses", unavailable)

    def run_test_process(_plan, _exe, _storage, *, stop_event, tick):
        tick(SimpleNamespace(pid=12345))
        assert read_state(plan)["gatusReady"] is False
        assert read_state(plan)["gatusErrorCode"] == "gatus_unavailable"
        stop_event.set()
        return 0

    monkeypatch.setattr("app.monitoring.automation.run_gatus", run_test_process)
    assert run_automation(config, stop_event=stop) == 0
