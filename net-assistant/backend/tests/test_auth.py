"""Real temporary SQLite/HTTP authentication; never initializes the working database."""
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.discovery.store import initialize_database
from app.main import create_app

PASSWORD = "isolated-test-password-729!"


def setup(tmp_path):
    from app.auth.store import AuthStore
    db = initialize_database(tmp_path / "access.sqlite")
    store = AuthStore(db.path)
    store.create_user("administrator", PASSWORD, "admin")
    return db, store


def login(client, username="administrator", password=PASSWORD):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrfToken"]}


def test_anonymous_business_reads_denied_by_default_without_database_creation(tmp_path):
    path = tmp_path / "absent.sqlite"
    with TestClient(create_app(database_path=path), base_url="https://testserver") as client:
        response = client.get("/api/v1/assets")
        assert response.status_code == 401
        assert response.json()["code"] == "authentication_required"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-request-id"] == response.json()["requestId"]
        assert client.get("/health/live").status_code == 200
    assert not path.exists()


def test_login_cookie_me_csrf_logout_and_server_revocation(tmp_path):
    db, store = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        headers = login(client)
        cookie = client.cookies.get("na_session")
        assert cookie and len(cookie) >= 40
        me = client.get("/api/v1/auth/me")
        assert me.json()["user"]["role"] == "admin"
        assert me.json()["csrfToken"] == headers["X-CSRF-Token"]
        assert client.get("/api/v1/assets").status_code == 200
        assert client.post("/api/v1/auth/logout").status_code == 403
        response = client.post("/api/v1/auth/logout", headers=headers)
        assert response.status_code == 200
        client.cookies.set("na_session", cookie)
        assert client.get("/api/v1/assets").status_code == 401
    with sqlite3.connect(db.path) as conn:
        stored = str(conn.execute("SELECT * FROM auth_sessions").fetchall())
        assert cookie not in stored
        assert PASSWORD not in str(conn.execute("SELECT * FROM auth_users").fetchall())


def test_cookie_flags_origin_protection_and_no_public_registration(tmp_path):
    db, _ = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        response = client.post("/api/v1/auth/login", json={"username": "administrator", "password": PASSWORD},
                               headers={"Origin": "https://evil.invalid"})
        assert response.status_code == 403
        response = client.post("/api/v1/auth/login", json={"username": "administrator", "password": PASSWORD})
        cookie = response.headers["set-cookie"].lower()
        assert all(flag in cookie for flag in ("httponly", "secure", "samesite=strict"))
        assert client.post("/api/v1/auth/register", json={}).status_code in (401, 403, 404)


def test_persistent_rate_limit_and_generic_bad_credentials(tmp_path):
    db, store = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        for _ in range(5):
            response = client.post("/api/v1/auth/login",
                                   json={"username": "administrator", "password": "incorrect"})
            assert response.status_code == 401
            assert response.json()["code"] == "invalid_credentials"
        assert client.post("/api/v1/auth/login",
                           json={"username": "administrator", "password": PASSWORD}).status_code == 429
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        assert client.post("/api/v1/auth/login",
                           json={"username": "administrator", "password": PASSWORD}).status_code == 429


def test_account_disable_and_password_change_revoke_existing_sessions(tmp_path):
    db, store = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        headers = login(client)
        assert client.post("/api/v1/auth/password", headers=headers, json={
            "currentPassword": PASSWORD, "newPassword": "a-different-secure-password-18!"
        }).status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 401
        login(client, password="a-different-secure-password-18!")
        store.disable_user("administrator")
        assert client.get("/api/v1/assets").status_code == 401


@pytest.mark.parametrize("intervening_action", ["reset", "logout", "expiry"])
def test_password_change_rechecks_authorization_at_commit(tmp_path, monkeypatch, intervening_action):
    import app.auth.store as auth
    from app.discovery.api import ApiError

    db, store = setup(tmp_path)
    token = store.login("administrator", PASSWORD, "127.0.0.1")["token"]
    principal = store.authenticate(token)
    admin_password = "admin-reset-password-195!"
    verify = auth.verify_password

    # Deterministically interleave another action after verifying the old password.
    def verify_then_interleave(password, encoded):
        assert verify(password, encoded)
        if intervening_action == "reset":
            store.reset_password("administrator", admin_password)
        elif intervening_action == "logout":
            store.logout(principal)
        else:
            store.clock = lambda: principal.expires_at
        return True

    monkeypatch.setattr(auth, "verify_password", verify_then_interleave)
    with pytest.raises(ApiError) as exc:
        store.change_password(principal, PASSWORD, "pending-password-change-773!")
    assert exc.value.status == 401
    with sqlite3.connect(db.path) as conn:
        encoded = conn.execute("SELECT password_hash FROM auth_users").fetchone()[0]
        audit_count = conn.execute("SELECT count(*) FROM access_audit WHERE action='password_reset'").fetchone()[0]
    assert verify(admin_password if intervening_action == "reset" else PASSWORD, encoded)
    assert audit_count == (1 if intervening_action == "reset" else 0)


def test_idle_absolute_expiry_and_password_hash_salt(tmp_path):
    db, store = setup(tmp_path)
    store.create_user("second", PASSWORD, "viewer")
    with sqlite3.connect(db.path) as conn:
        hashes = [row[0] for row in conn.execute("SELECT password_hash FROM auth_users")]
        assert hashes[0] != hashes[1]
    instant = time.time()
    store.clock = lambda: instant
    result = store.login("administrator", PASSWORD, "127.0.0.1")
    token = result["token"]
    instant += 1801
    assert store.authenticate(token) is None
    result = store.login("administrator", PASSWORD, "127.0.0.1")
    token = result["token"]
    for _ in range(17):
        instant += 1700
        principal = store.authenticate(token)
    assert principal is None


def test_password_and_role_validation_and_no_anonymous_write_bypass(tmp_path):
    db, store = setup(tmp_path)
    with pytest.raises(ValueError):
        store.create_user("weak", "short", "admin")
    with pytest.raises(ValueError):
        store.create_user("badrole", PASSWORD, "superuser")
    with TestClient(create_app(database_path=db.path, allow_anonymous_reads=True),
                    base_url="https://testserver") as client:
        assert client.get("/api/v1/assets").status_code == 200
        assert client.post("/api/v1/terminal/sessions", json={"targetId": "anything"}).status_code == 401


def test_contract_declares_cookie_and_csrf_and_unified_error_shape(tmp_path):
    app = create_app(database_path=tmp_path / "missing.sqlite")
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["sessionCookie"]["in"] == "cookie"
    assert schema["paths"]["/api/v1/assets"]["get"]["security"] == [{"sessionCookie": []}]
    assert schema["paths"]["/api/v1/auth/login"]["post"]["security"] == []
    assert schema["paths"]["/api/v1/terminal/sessions"]["post"]["security"] == [
        {"sessionCookie": [], "csrfHeader": []}]
    assert schema["paths"]["/api/v1/assets"]["get"]["responses"]["401"]["content"][
        "application/json"]["schema"]["$ref"].endswith("/ApiErrorEnvelope")


def test_http_login_requires_explicit_loopback_and_does_not_trust_forwarded_host(tmp_path):
    db, _ = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="http://localhost") as client:
        assert client.post("/api/v1/auth/login",
                           json={"username": "administrator", "password": PASSWORD}).status_code == 400
    with TestClient(create_app(database_path=db.path, allow_insecure_local_http=True),
                    base_url="http://127.0.0.1") as client:
        headers = login(client)
        assert client.get("/api/v1/auth/me").status_code == 200
    with TestClient(create_app(database_path=db.path, allow_insecure_local_http=True),
                    base_url="http://external.invalid") as client:
        assert client.post("/api/v1/auth/login", headers={"X-Forwarded-Host": "localhost"},
                           json={"username": "administrator", "password": PASSWORD}).status_code == 400


def test_oversized_login_and_terminal_payloads_are_bounded(tmp_path):
    db, _ = setup(tmp_path)
    with TestClient(create_app(database_path=db.path), base_url="https://testserver") as client:
        response = client.post("/api/v1/auth/login", content=b"x" * 32769,
                               headers={"Content-Type": "application/json"})
        assert response.status_code == 413
        headers = login(client)
        response = client.post("/api/v1/terminal/sessions", content=b"x" * 32769,
                               headers={**headers, "Content-Type": "application/json"})
        assert response.status_code == 413


def test_real_loopback_http_login_cookie_authenticated_read_and_logout(tmp_path):
    import httpx
    from test_local_tool_integration import live_api
    db, _ = setup(tmp_path)
    app = create_app(database_path=db.path, allow_insecure_local_http=True)
    with live_api(app) as base_url, httpx.Client(base_url=base_url, trust_env=False) as client:
        assert client.get("/api/v1/assets").status_code == 401
        response = client.post("/api/v1/auth/login",
                               json={"username": "administrator", "password": PASSWORD})
        assert response.status_code == 200
        assert response.json()["expiresAt"].endswith("Z")
        assert client.get("/api/v1/assets").status_code == 200
        assert client.get("/api/v1/terminal/targets").json() == {"items": []}
        assert client.post("/api/v1/auth/logout",
            headers={"X-CSRF-Token": response.json()["csrfToken"]}).status_code == 200
        assert client.get("/api/v1/assets").status_code == 401
