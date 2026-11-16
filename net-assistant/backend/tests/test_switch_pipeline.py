import asyncio
import json
from pathlib import Path
from fastapi.testclient import TestClient


def test_real_sqlite_http_roundtrip_keeps_failure_latest_and_history(tmp_path):
    from app.switches.store import SwitchStore
    from app.discovery.store import initialize_database
    from app.main import create_app
    db = initialize_database(tmp_path / "test.sqlite")
    store = SwitchStore(db)
    first = store.begin("10.99.0.2", "lab", "isolated-scope")
    sample = {"source": "snmpv3_readonly", "observedAt": "2026-11-16T00:00:00Z",
              "system": {"name": "isolated", "objectId": "1.3.6.1.4.1.4881.1"},
              "interfaces": [], "forwarding": [], "lldp": [], "capabilities": {}}
    saved = store.finish(first, "completed", snapshot=sample)
    second = store.begin("10.99.0.2", "lab", "isolated-scope")
    store.finish(second, "failed", error_code="snmp_timeout")
    with TestClient(create_app(allow_anonymous_reads=True, database_path=db.path)) as client:
        devices = client.get("/api/v1/switches").json()
        assert len(devices["items"]) == 1
        device = devices["items"][0]
        assert device["latest"]["state"] == "failed"
        assert device["latest"]["snapshot"] is None
        result = client.get(f"/api/v1/switches/{device['id']}/snapshots?limit=1")
        assert result.status_code == 200
        page = result.json()
        assert page["items"][0]["snapshot"] == sample
        assert page["nextCursor"] is not None
        assert client.get(f"/api/v1/switch-snapshots/{saved['id']}").json()["snapshot"] == sample
        assert client.get("/api/v1/switches/status").json()["state"] == "not_configured"
        assert client.get("/api/v1/switches/not-a-device").status_code == 404
    # Reads are genuinely read-only, not collection triggers.
    assert len(store.runs()["items"]) == 2


def test_unconfigured_credentials_emit_no_packets_and_auto_reload(tmp_path, monkeypatch):
    from app.switches.worker import run_cycle
    from app.switches.config import load_switch_plan
    from app.discovery.store import initialize_database
    from test_switch_config import config
    path = config(tmp_path)
    monkeypatch.delenv("TEST_SWITCH_AUTH", raising=False)
    monkeypatch.delenv("TEST_SWITCH_PRIV", raising=False)
    db = initialize_database(tmp_path / "test.sqlite")
    calls = []

    async def fake_collect(address, profile, secrets, plan):
        calls.append(address)
        return {"source": "snmpv3_readonly", "observedAt": "2026-11-16T00:00:00Z",
                "system": {"name": "test", "objectId": "1.3.6.1.4.1.4881.1"},
                "interfaces": [], "forwarding": [], "lldp": [],
                "capabilities": {"interfaces": {"state": "available"}}}

    result = asyncio.run(run_cycle(load_switch_plan(path), db, collect=fake_collect))
    assert result["state"] == "waiting_configuration"
    assert calls == []
    monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
    monkeypatch.setenv("TEST_SWITCH_PRIV", "isolated-priv-secret")
    result = asyncio.run(run_cycle(load_switch_plan(path), db, collect=fake_collect))
    assert result["state"] == "completed"
    assert calls == ["10.99.0.2"]
    from app.switches.store import SwitchStore
    assert len(SwitchStore(db).devices()["items"]) == 1
    assert "isolated-auth-secret" not in json.dumps(result)


def test_failed_or_unsupported_probe_never_registers_fake_device(tmp_path, monkeypatch):
    from app.switches.worker import run_cycle
    from app.switches.config import load_switch_plan
    from app.switches.snmp import SnmpFailure
    from app.switches.store import SwitchStore
    from app.discovery.store import initialize_database
    from test_switch_config import config
    monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
    monkeypatch.setenv("TEST_SWITCH_PRIV", "isolated-priv-secret")
    plan = load_switch_plan(config(tmp_path))
    db = initialize_database(plan.database)

    async def failure(*args):
        raise SnmpFailure("snmp_timeout")

    result = asyncio.run(run_cycle(plan, db, collect=failure))
    assert result["counts"]["failed"] == 1
    store = SwitchStore(db)
    assert store.devices()["items"] == []
    assert store.runs()["items"][0]["errorCode"] == "snmp_timeout"


def test_worker_storage_failure_cancels_other_inflight_targets_before_returning(tmp_path, monkeypatch):
    from app.switches.worker import run_cycle
    from app.switches.config import load_switch_plan
    from app.switches.store import SwitchStore
    from app.discovery.store import initialize_database
    from test_switch_config import config
    monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
    monkeypatch.setenv("TEST_SWITCH_PRIV", "isolated-priv-secret")
    path = config(tmp_path)
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"name": "two", "targets": ["10.99.0.0/30"], "ports": [80]}), encoding="utf-8")
    plan = load_switch_plan(path)
    db = initialize_database(plan.database)
    original = SwitchStore.begin
    cancelled = []

    def begin(self, address, *args):
        if address == "10.99.0.2":
            raise OSError("isolated storage failure")
        return original(self, address, *args)

    async def blocked(address, *args):
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.append(address)
            raise

    monkeypatch.setattr(SwitchStore, "begin", begin)
    async def scenario():
        try:
            await run_cycle(plan, db, collect=blocked)
        except BaseException:
            pass
        await asyncio.sleep(0)
        assert cancelled == ["10.99.0.1"]
        assert all(row["state"] != "running" for row in SwitchStore(db).runs()["items"])
    asyncio.run(scenario())
