"""Domain/HTTP tests with an explicitly synthetic transport, not real-switch evidence."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from test_auth import PASSWORD, login, setup


class SyntheticTransport:
    """Boundary fixture: deterministic responses and fault injection, no network traffic."""
    writes = []
    failure = None
    closed = 0

    def __init__(self, target):
        self.target = target

    def connect(self):
        pass

    def run(self, command):
        self.writes.append(command)
        if self.failure:
            from app.terminal.transport import TransportFailure
            raise TransportFailure(self.failure, sent=True)
        return f"{command}\r\nsynthetic-switch-output\r\nlab#"

    def close(self):
        type(self).closed += 1


@pytest.fixture
def terminal(tmp_path, monkeypatch):
    from app.terminal import transport
    monkeypatch.setattr(transport, "OpenSSHTransport", SyntheticTransport)
    SyntheticTransport.writes = []
    SyntheticTransport.failure = None
    SyntheticTransport.closed = 0
    db, store = setup(tmp_path)
    store.create_user("operator", PASSWORD, "operator")
    store.create_user("viewer", PASSWORD, "viewer")
    key = tmp_path / "isolated-key"
    hosts = tmp_path / "isolated-known-hosts"
    key.write_text("fixture-only-not-a-real-key")
    hosts.write_text("fixture-only-not-a-real-host-key")
    config = tmp_path / "terminal.json"
    config.write_text(json.dumps({"targets": [
        {"id": "lab", "label": "isolated lab", "address": "127.0.0.1", "port": 22222,
         "username": "device-admin", "private_key": str(key), "known_hosts": str(hosts),
         "vendor": "cisco", "platform": "ios", "version": "fixture",
         "compatibility_confirmed": True, "allowed_users": ["administrator", "operator", "viewer"],
         "allowed_commands": ["version", "interfaces", "interface_description", "port_shutdown"]},
        {"id": "private", "label": "not granted", "address": "127.0.0.2",
         "username": "device-admin", "private_key": str(key), "known_hosts": str(hosts),
         "vendor": "huawei", "platform": "vrp", "version": "fixture",
         "allowed_users": [], "allowed_commands": []}
    ]}), encoding="utf-8")
    app = create_app(database_path=db.path, terminal_config_path=config)
    with TestClient(app, base_url="https://testserver") as client:
        headers = login(client)
        yield client, headers, db, store, app


def session(client, headers):
    result = client.post("/api/v1/terminal/sessions", json={"targetId": "lab"}, headers=headers)
    assert result.status_code == 200, result.text
    return result.json()["id"]


def preview(client, headers, sid, command="version", parameters=None):
    return client.post(f"/api/v1/terminal/sessions/{sid}/operations", headers=headers,
                       json={"commandId": command, "parameters": parameters or {}})


def test_unconfigured_has_real_empty_directories_and_no_fake_configuration_success(tmp_path):
    db, store = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        headers = login(client)
        assert client.get("/api/v1/terminal/targets").json()["items"] == []
        assert len(client.get("/api/v1/terminal/vendors").json()["items"]) == 4
        assert client.get("/api/v1/terminal/configuration-templates").json() == {
            "items": [], "executionSupported": False}
        assert client.post("/api/v1/terminal/configuration-runs", json={},
                           headers=headers).status_code == 501
        assert client.get("/api/v1/terminal/configuration-templates/missing").status_code == 404
        assert client.post("/api/v1/terminal/configuration-templates/missing/preview",
                           json={"targetId": "missing", "parameters": {}}, headers=headers).status_code == 404
        assert client.post("/api/v1/terminal/configuration-plans/missing/confirm",
                           json={"firstConfirmed": True, "phrase": "我确认执行该操作"},
                           headers=headers).status_code == 404
        response = client.get("/api/v1/terminal/configuration-runs/missing")
        assert response.status_code == 404
        assert response.json()["code"] == "configuration_run_not_found"
        schema = client.get("/openapi.json").json()
        assert schema["paths"]["/api/v1/terminal/configuration-templates/{template_id}/preview"]["post"][
            "operationId"] == "previewConfigurationTemplate"


def test_target_permissions_roles_and_server_only_connection_details(terminal):
    client, headers, db, store, app = terminal
    targets = client.get("/api/v1/terminal/targets").json()["items"]
    assert [t["id"] for t in targets] == ["lab"]
    assert not ({"private_key", "known_hosts", "username"} & targets[0].keys())
    assert "device-admin" not in json.dumps(targets)
    assert str(db.path.parent) not in json.dumps(targets)
    assert client.post("/api/v1/terminal/sessions", headers=headers,
                       json={"targetId": "private"}).status_code == 404
    assert client.post("/api/v1/terminal/sessions", headers=headers,
                       json={"targetId": "lab", "address": "192.0.2.9"}).status_code == 422
    client.post("/api/v1/auth/logout", headers=headers)
    headers = login(client, "viewer")
    assert client.post("/api/v1/terminal/sessions", headers=headers,
                       json={"targetId": "lab"}).status_code == 403


def test_preview_does_not_send_unknown_commands_or_parameter_injection(terminal):
    client, headers, *_ = terminal
    sid = session(client, headers)
    response = preview(client, headers, sid)
    assert response.status_code == 200
    assert response.json()["commands"] == ["show version"]
    assert response.json()["state"] == "prepared"
    assert SyntheticTransport.writes == []
    for command, parameters in [
        ("raw", {"command": "erase startup-config"}),
        ("interface_description", {"interface": "Gi0/1\nreload", "description": "x"}),
        ("interface_description", {"interface": "Gi0/1", "description": "x\nreload"}),
        ("version", {"unexpected": "value"}),
    ]:
        assert preview(client, headers, sid, command, parameters).status_code == 422
    assert SyntheticTransport.writes == []


def test_durable_intent_execution_and_same_operation_never_replays(terminal):
    client, headers, db, *_ = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid).json()
    url = f"/api/v1/terminal/operations/{op['id']}/execute"
    result = client.post(url, headers=headers, json={})
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "completed"
    assert "synthetic-switch-output" in result.json()["output"]
    again = client.post(url, headers=headers, json={})
    assert again.json()["state"] == "completed"
    assert SyntheticTransport.writes == ["show version"]
    with sqlite3.connect(db.path) as conn:
        actions = [row[0] for row in conn.execute(
            "SELECT action FROM access_audit WHERE object_id=? ORDER BY sequence", (op["id"],))]
    assert actions == ["command_prepared", "command_started", "command_step", "command_completed"]


def test_high_risk_requires_both_confirmations_bound_to_specific_operation(terminal):
    client, headers, *_ = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid, "port_shutdown", {"interface": "Gi0/1"}).json()
    root = f"/api/v1/terminal/operations/{op['id']}"
    assert client.post(root + "/execute", json={}, headers=headers).status_code == 409
    assert client.post(root + "/confirm", json={"firstConfirmed": True, "phrase": "yes"},
                       headers=headers).status_code == 422
    confirmation = client.post(root + "/confirm", headers=headers,
        json={"firstConfirmed": True, "phrase": "我确认执行该操作"})
    assert confirmation.status_code == 200, confirmation.text
    token = confirmation.json()["confirmationToken"]
    another = preview(client, headers, sid, "port_shutdown", {"interface": "Gi0/2"}).json()
    assert client.post(f"/api/v1/terminal/operations/{another['id']}/execute",
                       json={"confirmationToken": token}, headers=headers).status_code == 409
    result = client.post(root + "/execute", json={"confirmationToken": token}, headers=headers)
    assert result.json()["state"] == "completed"
    assert SyntheticTransport.writes == ["configure terminal", "interface Gi0/1", "shutdown", "end"]
    assert client.post(root + "/execute", json={"confirmationToken": token}, headers=headers).status_code == 200
    assert len(SyntheticTransport.writes) == 4


def test_cross_user_and_cross_platform_session_isolation(terminal):
    client, headers, *_ = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid).json()
    # A second login is not the terminal's owning platform session, even for the same username.
    headers = login(client)
    assert client.get(f"/api/v1/terminal/sessions/{sid}").status_code == 404
    headers = login(client, "operator")
    assert client.get(f"/api/v1/terminal/operations/{op['id']}").status_code == 404
    assert client.post(f"/api/v1/terminal/operations/{op['id']}/execute",
                       json={}, headers=headers).status_code == 404


def test_disconnect_records_unknown_and_does_not_retry(terminal):
    client, headers, db, *_ = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid).json()
    SyntheticTransport.failure = "ssh_disconnected"
    url = f"/api/v1/terminal/operations/{op['id']}/execute"
    response = client.post(url, json={}, headers=headers)
    assert response.json()["state"] == "result_unknown"
    assert response.json()["errorCode"] == "ssh_disconnected"
    assert client.get(f"/api/v1/terminal/sessions/{sid}").json()["state"] == "disconnected"
    assert client.post(url, json={}, headers=headers).json()["state"] == "result_unknown"
    assert len(SyntheticTransport.writes) == 1


def test_confirmation_expiry_logout_closes_transport_and_audit_failure_blocks_send(terminal, monkeypatch):
    client, headers, db, store, app = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid).json()
    with sqlite3.connect(db.path) as conn:
        conn.execute("UPDATE terminal_operations SET expires_at=0 WHERE id=?", (op["id"],))
    assert client.post(f"/api/v1/terminal/operations/{op['id']}/execute",
                       json={}, headers=headers).status_code == 409
    op = preview(client, headers, sid).json()
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("injected audit storage outage")
    monkeypatch.setattr(app.state.terminal.store, "audit", fail)
    assert client.post(f"/api/v1/terminal/operations/{op['id']}/execute",
                       json={}, headers=headers).status_code == 503
    assert SyntheticTransport.writes == []
    monkeypatch.undo()
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert SyntheticTransport.closed >= 1


def test_final_audit_failure_closes_channel_and_recovers_unknown_not_running_forever(terminal, monkeypatch):
    client, headers, db, store, app = terminal
    sid = session(client, headers)
    op = preview(client, headers, sid).json()
    original = app.state.terminal.store.audit
    def fail_final(conn, user_id, action, *args, **kwargs):
        if action == "command_completed":
            raise sqlite3.OperationalError("injected final commit failure")
        return original(conn, user_id, action, *args, **kwargs)
    monkeypatch.setattr(app.state.terminal.store, "audit", fail_final)
    response = client.post(f"/api/v1/terminal/operations/{op['id']}/execute", json={}, headers=headers)
    assert response.status_code == 503
    assert SyntheticTransport.closed >= 1
    monkeypatch.undo()
    assert client.get(f"/api/v1/terminal/operations/{op['id']}").json()["state"] == "result_unknown"
    assert client.get(f"/api/v1/terminal/sessions/{sid}").json()["state"] != "ready"
    assert SyntheticTransport.writes == ["show version"]


def test_cli_rejection_is_not_success_and_device_mutation_may_be_partial(terminal, monkeypatch):
    client, headers, db, store, app = terminal
    sid = session(client, headers)
    def rejected(self, command):
        return command + "\n% Invalid input detected at '^' marker.\nlab#"
    monkeypatch.setattr(SyntheticTransport, "run", rejected)
    op = preview(client, headers, sid).json()
    result = client.post(f"/api/v1/terminal/operations/{op['id']}/execute", json={}, headers=headers)
    assert result.json()["state"] == "failed"
    assert result.json()["errorCode"] == "device_command_rejected"
    assert result.json()["businessVerified"] is False


def test_multibyte_output_limit_is_in_bytes_and_still_marks_unknown(terminal, monkeypatch):
    client, headers, *_ = terminal
    sid = session(client, headers)
    monkeypatch.setattr(SyntheticTransport, "run", lambda self, command: "汉" * 20000 + "\nlab#")
    op = preview(client, headers, sid, "interface_description",
                 {"interface": "Gi0/1", "description": "test"}).json()
    result = client.post(f"/api/v1/terminal/operations/{op['id']}/execute", json={}, headers=headers).json()
    assert result["state"] == "result_unknown"
    assert result["errorCode"] == "output_limit_exceeded"
    assert len(result["output"].encode("utf-8")) <= 65536


def test_multi_vendor_templates_not_claimed_as_real_device_verified(tmp_path):
    from app.terminal.catalog import catalog, render
    from test_terminal_transport import target
    expected = [
        ("cisco", "ios", "show version"), ("ruijie", "rgos", "show version"),
        ("huawei", "vrp", "display version"), ("h3c", "comware", "display version")]
    for vendor, platform, command in expected:
        item = target(tmp_path, vendor=vendor, platform=platform, compatibility_confirmed=True,
                      allowed_commands=["version"])
        assert render(item, "version", {}) == ([command], "low")
        assert all(row["realDeviceVerified"] is False for row in catalog(vendor, item))
    item = target(tmp_path, compatibility_confirmed=False, allowed_commands=["version"])
    from app.discovery.api import ApiError
    with pytest.raises(ApiError):
        render(item, "version", {})
