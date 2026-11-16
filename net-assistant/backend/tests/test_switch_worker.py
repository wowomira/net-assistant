import json
import threading
import time


def test_automation_accepts_switch_plan_and_resolves_relative_path(tmp_path):
    from app.monitoring.automation import load_automation
    path = tmp_path / "automation.json"
    path.write_text(json.dumps({
        "device_id": "00000000-0000-4000-8000-000000000001",
        "device_label": "isolated", "database": "test.sqlite",
        "monitoring_plan": "monitor.json", "storage": "gatus.sqlite",
        "switch_plan": "switches.json",
    }), encoding="utf-8")
    assert load_automation(path).switch_plan == tmp_path / "switches.json"


def test_worker_heartbeats_without_credentials_and_reloads_configuration(tmp_path, monkeypatch):
    from app.switches.worker import run_worker
    from test_switch_config import config
    monkeypatch.delenv("TEST_SWITCH_AUTH", raising=False)
    monkeypatch.delenv("TEST_SWITCH_PRIV", raising=False)
    path = config(tmp_path)
    stop = threading.Event()
    errors = []
    def run():
        try:
            run_worker(path, stop_event=stop)
        except BaseException as error:
            errors.append(type(error).__name__)
    thread = threading.Thread(target=run)
    thread.start()
    state_path = tmp_path / "runtime" / "switch-state.json"
    def wait_state(expected):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if state["state"] == expected:
                    return state
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        raise AssertionError({"errors": errors, "expected": expected})
    try:
        state = wait_state("waiting_configuration")
        assert state["lastCycle"]["counts"]["attempted"] == 0
        value = json.loads(path.read_text(encoding="utf-8"))
        value["enabled"] = False
        path.write_text(json.dumps(value), encoding="utf-8")
        state = wait_state("disabled")
        assert state["lastCycle"]["counts"]["attempted"] == 0
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert errors == []
    assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == "stopped"


def test_missing_credentials_do_not_hide_stopped_or_stale_worker(tmp_path, monkeypatch):
    from app.switches.config import load_switch_plan
    from app.switches.worker import read_runtime, write_runtime, identity
    from app.discovery.types import utc_now
    from test_switch_config import config
    monkeypatch.delenv("TEST_SWITCH_AUTH", raising=False)
    monkeypatch.delenv("TEST_SWITCH_PRIV", raising=False)
    plan = load_switch_plan(config(tmp_path))
    write_runtime(plan, {"state": "stopped", "heartbeatAt": utc_now(),
                         "configIdentity": identity(plan), "lastCycle": None})
    assert read_runtime(plan)["state"] == "stopped"
    write_runtime(plan, {"state": "waiting_configuration", "heartbeatAt": "2000-01-01T00:00:00Z",
                         "configIdentity": identity(plan), "lastCycle": None})
    assert read_runtime(plan)["state"] == "stale"
