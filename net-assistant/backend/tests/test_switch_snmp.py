"""Real authenticated/encrypted loopback SNMP, using isolated synthetic MIB data."""
import asyncio
import json
import socket
import threading
import time
import pytest


@pytest.mark.parametrize("auth_protocol", ["SHA", "SHA256", "SHA512"])
def test_actual_udp_snmpv3_collection_onboards_to_sqlite_and_unsupported_tables_stay_empty(tmp_path, monkeypatch, auth_protocol):
    # This test would fail if authPriv, numeric OIDs, bulk traversal or worker persistence broke.
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.proto import rfc1902, rfc1905
    from pysnmp.smi.instrum import AbstractMibInstrumController
    from app.switches import projection as mib
    from app.switches.config import load_switch_plan
    from app.switches.worker import run_cycle
    from app.switches.store import SwitchStore
    from app.discovery.store import initialize_database
    from test_switch_config import config as make_config
    monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
    monkeypatch.setenv("TEST_SWITCH_PRIV", "isolated-priv-secret")
    path = make_config(tmp_path, timeout_seconds=0.5)
    settings = json.loads(path.read_text(encoding="utf-8"))
    settings["profiles"][0]["auth_protocol"] = auth_protocol
    path.write_text(json.dumps(settings), encoding="utf-8")
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "name": "loopback-only", "targets": ["127.0.0.1"], "ports": [80], "allow_loopback": True,
    }), encoding="utf-8")

    values = {
        mib.SYSTEM["description"]: rfc1902.OctetString("ISOLATED protocol fixture"),
        mib.SYSTEM["objectId"]: rfc1902.ObjectIdentifier("1.3.6.1.4.1.4881.1.1.10.1.999"),
        mib.SYSTEM["name"]: rfc1902.OctetString("isolated-agent"),
        mib.SYSTEM["uptime"]: rfc1902.TimeTicks(12345),
        mib.IF["name"] + ".107": rfc1902.OctetString("Gi0/7"),
        mib.IF["operStatus"] + ".107": rfc1902.Integer32(1),
        mib.IF["adminStatus"] + ".107": rfc1902.Integer32(1),
        mib.IF["inOctets"] + ".107": rfc1902.Counter64(2**54 + 1),
    }
    data = {tuple(map(int, oid.split("."))): value for oid, value in values.items()}
    keys = sorted(data)
    operations = []

    class Instrumentation(AbstractMibInstrumController):
        def read_variables(self, *bindings, **kwargs):
            operations.append("GET")
            return [(oid, data.get(tuple(oid), rfc1905.noSuchInstance)) for oid, _ in bindings]

        def read_next_variables(self, *bindings, **kwargs):
            operations.append("NEXT")
            result = []
            for oid, _ in bindings:
                found = next((key for key in keys if key > tuple(oid)), None)
                result.append((rfc1902.ObjectName(found), data[found]) if found else (oid, rfc1905.endOfMibView))
            return result

        def write_variables(self, *bindings, **kwargs):
            pytest.fail("Collector must never issue SET.")

    async def scenario():
        agent = engine.SnmpEngine()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.setblocking(False)
        transport = udp.UdpTransport().open_server_mode(sock=sock)
        config.add_transport(agent, udp.DOMAIN_NAME, transport)
        config.add_v3_user(
            agent, "readonly", {
                "SHA": config.USM_AUTH_HMAC96_SHA, "SHA256": config.USM_AUTH_HMAC192_SHA256,
                "SHA512": config.USM_AUTH_HMAC384_SHA512,
            }[auth_protocol], "isolated-auth-secret",
            config.USM_PRIV_CFB128_AES, "isolated-priv-secret")
        config.add_vacm_user(agent, 3, "readonly", "authPriv", (1,), (), ())
        ctx = context.SnmpContext(agent)
        ctx.unregister_context_name(b"")
        ctx.register_context_name(b"", Instrumentation())
        responders = [cmdrsp.GetCommandResponder(agent, ctx), cmdrsp.BulkCommandResponder(agent, ctx)]
        await transport._lport
        settings = json.loads(path.read_text(encoding="utf-8"))
        settings["port"] = port
        path.write_text(json.dumps(settings), encoding="utf-8")
        plan = load_switch_plan(path)
        db = initialize_database(plan.database)
        try:
            result = await run_cycle(plan, db)
            assert result["counts"]["completed"] == 1, result
            store = SwitchStore(db)
            devices = store.devices()["items"]
            assert len(devices) == 1
            snapshot = devices[0]["latest"]["snapshot"]
            assert snapshot["system"]["name"] == "isolated-agent"
            assert snapshot["system"]["uptimeSeconds"] == 123.45
            assert snapshot["interfaces"][0]["inOctets"] == str(2**54 + 1)
            assert snapshot["forwarding"] == []
            assert snapshot["lldp"] == []
            assert snapshot["capabilities"]["lldp"]["state"] == "no_data"
            assert "GET" in operations and "NEXT" in operations
            assert len(store.runs()["items"]) == 1
            # The same real protocol result is exposed over the actual ASGI HTTP stack.
            from fastapi.testclient import TestClient
            from app.main import create_app
            with TestClient(create_app(allow_anonymous_reads=True, database_path=db.path)) as client:
                response = client.get(f"/api/v1/switches/{devices[0]['id']}/snapshots/latest")
                assert response.status_code == 200
                assert response.json()["snapshot"] == snapshot
                assert "isolated-auth-secret" not in response.text
            if auth_protocol == "SHA256":
                monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-wrong-secret")
                failed = await run_cycle(plan, db)
                assert failed["counts"]["failed"] == 1
                latest = store.device(devices[0]["id"])["latest"]
                assert latest["state"] == "failed" and latest["snapshot"] is None
                monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
                recovered = await run_cycle(plan, db)
                assert recovered["counts"]["completed"] == 1
                assert store.device(devices[0]["id"])["latest"]["state"] == "completed"
                assert len(store.runs()["items"]) == 3
                # Real independent worker, actual wall clock (no mocked timer), still loopback only.
                from app.switches.worker import run_worker
                values = json.loads(path.read_text(encoding="utf-8"))
                values["interval_seconds"] = 30
                path.write_text(json.dumps(values), encoding="utf-8")
                stop = threading.Event()
                worker = asyncio.create_task(asyncio.to_thread(run_worker, path, stop_event=stop))
                try:
                    deadline = time.monotonic() + 65
                    while time.monotonic() < deadline:
                        saved = store.runs()["items"]
                        if len(saved) >= 5 and saved[-1]["state"] == "completed":
                            from datetime import datetime
                            gap = (datetime.fromisoformat(saved[-1]["startedAt"].replace("Z", "+00:00"))
                                   - datetime.fromisoformat(saved[-2]["finishedAt"].replace("Z", "+00:00"))).total_seconds()
                            assert gap >= 29.5
                            break
                        if worker.done():
                            worker.result()
                            raise AssertionError("Worker exited before the next cycle.")
                        await asyncio.sleep(0.2)
                    else:
                        raise AssertionError("Actual 30-second worker did not collect twice.")
                finally:
                    stop.set()
                    await asyncio.wait_for(worker, timeout=10)
        finally:
            for responder in responders:
                responder.close(agent)
            agent.close_dispatcher()
            db.engine.dispose()
    asyncio.run(scenario())


def test_loopback_timeout_is_not_a_successful_empty_snapshot(tmp_path):
    from app.switches.config import Profile, Credentials, SwitchPlan
    from app.switches.snmp import collect_switch, SnmpFailure
    from test_switch_config import config as make_config
    from app.switches.config import load_switch_plan
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))  # Bound but no responder; no unrelated process is contacted.
    plan = load_switch_plan(make_config(tmp_path)).model_copy(update={"port": sock.getsockname()[1], "timeout_seconds": 0.2})
    secret = Credentials(auth_key="isolated-auth-secret", priv_key="isolated-priv-secret")
    try:
        with pytest.raises(SnmpFailure, match="snmp_timeout"):
            asyncio.run(collect_switch("127.0.0.1", plan.profiles[0], secret, plan))
    finally:
        sock.close()
