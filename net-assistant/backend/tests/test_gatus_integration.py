"""The adapter must not turn missing/stale/invalid upstream data into health."""
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.main import create_app


@pytest.fixture
def anyio_backend():
    return "asyncio"


def plan(**changes):
    from app.monitoring.config import MonitoringPlan
    return MonitoringPlan.model_validate({
        "allowed_hosts": ["127.0.0.1"], "allow_loopback": True,
        "endpoints": [{"id": "local-web", "url": "http://127.0.0.1:9123/health",
                       "interval_seconds": 5}],
        **changes,
    })


def test_generated_config_preserves_tls_blocks_redirects_and_uses_separate_sqlite(tmp_path):
    from app.monitoring.config import render_gatus, write_gatus_config
    config = render_gatus(plan(), tmp_path / "gatus.sqlite", 18080)
    assert config["web"] == {"address": "127.0.0.1", "port": 18080}
    assert config["storage"]["type"] == "sqlite"
    assert config["storage"]["path"] == (tmp_path / "gatus.sqlite").as_posix()
    endpoint = config["endpoints"][0]
    assert endpoint["name"] == "local-web-e72d3fa04cb6"
    assert endpoint["client"]["insecure"] is False
    assert endpoint["client"]["ignore-redirect"] is True
    assert endpoint["conditions"] == ["[STATUS] == 200", "[RESPONSE_TIME] < 2000"]
    output = tmp_path / "config.yaml"
    write_gatus_config(plan(), output, tmp_path / "gatus.sqlite", 18080)
    assert json.loads(output.read_text("utf-8")) == config
    with pytest.raises(FileExistsError):
        write_gatus_config(plan(), output, tmp_path / "gatus.sqlite", 18080)


@pytest.mark.parametrize("url", [
    "http://10.0.0.9/", "http://user:password@127.0.0.1/", "file:///etc/passwd",
    "http://127.0.0.1/?token=secret", "http://127.0.0.1/#token",
    "tcp://127.0.0.1:22/not-valid", "http://127.0.0.1/${SECRET}",
])
def test_unapproved_targets_credentials_and_template_expansion_are_rejected(url):
    with pytest.raises(ValidationError):
        plan(endpoints=[{"id": "bad", "url": url}])


def test_duplicate_keys_loopback_and_public_targets_require_explicit_permission():
    with pytest.raises(ValidationError):
        plan(allow_loopback=False)
    with pytest.raises(ValidationError):
        plan(allowed_hosts=["8.8.8.8"], endpoints=[{"id": "dns", "url": "tcp://8.8.8.8:53"}])
    with pytest.raises(ValidationError):
        plan(endpoints=[{"id": "same", "url": "http://127.0.0.1/"}] * 2)


def test_tcp_and_certificate_conditions_are_not_http_status_guesses(tmp_path):
    from app.monitoring.config import render_gatus
    config = render_gatus(plan(endpoints=[
        {"id": "tcp", "url": "tcp://127.0.0.1:22"},
        {"id": "tls", "url": "https://127.0.0.1/", "certificate_days": 14},
    ]), tmp_path / "gatus.sqlite", 18080)
    assert config["endpoints"][0]["conditions"][0] == "[CONNECTED] == true"
    assert "[CERTIFICATE_EXPIRATION] > 336h" in config["endpoints"][1]["conditions"]


def test_empty_plan_cannot_be_rendered_as_a_runnable_monitor(tmp_path):
    from app.monitoring.config import render_gatus
    with pytest.raises(ValueError, match="endpoint"):
        render_gatus(plan(endpoints=[]), tmp_path / "gatus.sqlite", 18080)


def test_config_generation_refuses_foreign_existing_database_without_modification(tmp_path):
    import sqlite3
    from app.monitoring.config import render_gatus
    database = tmp_path / "other.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER)")
    before = database.read_bytes()
    with pytest.raises(ValueError, match="Gatus"):
        render_gatus(plan(), database, 18080)
    assert database.read_bytes() == before


def test_database_with_coincidentally_matching_table_names_is_still_refused(tmp_path):
    from contextlib import closing
    import sqlite3
    from app.monitoring.config import render_gatus
    database = tmp_path / "other.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE endpoints (id INTEGER)")
        connection.execute("CREATE TABLE endpoint_results (id INTEGER)")
        connection.commit()
    before = database.read_bytes()
    with pytest.raises(ValueError, match="Gatus"):
        render_gatus(plan(), database, 18080)
    assert database.read_bytes() == before


def test_runtime_refuses_missing_binary_and_never_creates_a_monitoring_db(tmp_path):
    from app.monitoring.runtime import run_gatus
    with pytest.raises(FileNotFoundError):
        run_gatus(plan(), tmp_path / "missing.exe", tmp_path / "gatus.sqlite")
    assert not (tmp_path / "gatus.sqlite").exists()


@pytest.mark.anyio
async def test_upstream_request_explicitly_reads_hundred_observations_not_default_page():
    from app.monitoring.client import GatusClient
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json=[])
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        respond), base_url="http://127.0.0.1:18080") as http:
        await GatusClient(plan(), http=http).statuses()
    assert requests[0].url.params["pageSize"] == "100"


@pytest.mark.anyio
async def test_status_and_history_normalize_nanoseconds_and_keep_real_observation_time():
    from app.monitoring.client import GatusClient
    now = datetime.now(timezone.utc)
    recent = now.isoformat()
    older = (now - timedelta(seconds=6)).isoformat()
    data = [{"key": "net-assistant_local-web-e72d3fa04cb6", "name": "local-web-e72d3fa04cb6", "group": "net-assistant",
             "results": [{"status": 503, "duration": 4000000, "success": False, "timestamp": older},
                         {"status": 200, "duration": 12000000, "success": True, "timestamp": recent}],
             "events": []}]
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=data)), base_url="http://127.0.0.1:18080") as http:
        result = await GatusClient(plan(), http=http).statuses()
    item = result["items"][0]
    assert item["status"] == "up"
    assert item["latest"]["durationMs"] == 12
    assert item["latest"]["observedAt"] == recent
    assert [entry["success"] for entry in item["history"]] == [False, True]
    assert item["assetId"] is None


@pytest.mark.anyio
async def test_stale_no_data_missing_and_unavailable_are_distinct():
    from app.monitoring.client import GatusClient, GatusError
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    for rows, expected in [
        ([], "not_configured"),
        ([{"key": "net-assistant_local-web-e72d3fa04cb6", "results": []}], "no_data"),
        ([{"key": "net-assistant_local-web-e72d3fa04cb6", "results": [
            {"duration": 1, "success": True, "timestamp": old}]}], "stale"),
    ]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=rows)), base_url="http://127.0.0.1:18080") as http:
            assert (await GatusClient(plan(), http=http).statuses())["items"][0]["status"] == expected
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(502)), base_url="http://127.0.0.1:18080") as http:
        with pytest.raises(GatusError, match="gatus_unavailable"):
            await GatusClient(plan(), http=http).statuses()


@pytest.mark.anyio
@pytest.mark.parametrize("data", [{}, [{"key": "net-assistant_local-web-e72d3fa04cb6", "results": [
    {"duration": -1, "success": "yes", "timestamp": "broken"}]}]])
async def test_malformed_upstream_is_error_not_empty_success(data):
    from app.monitoring.client import GatusClient, GatusError
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=data)), base_url="http://127.0.0.1:18080") as http:
        with pytest.raises(GatusError, match="gatus_invalid_response"):
            await GatusClient(plan(), http=http).statuses()


@pytest.mark.anyio
async def test_changed_target_or_health_condition_cannot_relabel_old_result_as_current_health():
    from app.monitoring.client import GatusClient
    old_key = plan().endpoints[0].key
    data = [{"key": old_key, "results": [{"status": 200, "duration": 1, "success": True,
                                       "timestamp": datetime.now(timezone.utc).isoformat()}]}]
    for endpoint in [
        {"id": "local-web", "url": "http://127.0.0.1:9123/different", "interval_seconds": 5},
        {"id": "local-web", "url": "http://127.0.0.1:9123/health",
         "interval_seconds": 5, "status_code": 204},
    ]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=data)), base_url="http://127.0.0.1:18080") as http:
            item = (await GatusClient(plan(endpoints=[endpoint]), http=http).statuses())["items"][0]
        assert item["status"] == "not_configured"
        assert item["latest"] is None


@pytest.mark.anyio
async def test_monitoring_api_disabled_without_configuration_does_not_create_database(tmp_path):
    path = tmp_path / "absent.sqlite"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(
        app=create_app(allow_anonymous_reads=True, database_path=path)), base_url="http://testserver") as client:
        response = await client.get("/api/v1/monitoring")
        assert response.status_code == 200
        assert response.json()["status"] == "not_configured"
        assert (await client.post("/api/v1/monitoring", json={})).status_code == 401
    assert not path.exists()
