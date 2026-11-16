import httpx
import pytest

from app.main import create_app
from app.discovery.config import ScanSettings
from app.discovery.store import initialize_database

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_readonly_queries_camelcase_and_no_scan_post(tmp_path):
    path = tmp_path / "test.sqlite"
    db = initialize_database(path)
    settings = ScanSettings(name="test", targets=["10.1.1.1"], ports=[80], discovery_ports=[80])
    scope_id, revision = db.save_scope(settings)
    job = db.begin_job(scope_id, revision, settings.snapshot())
    db.finish_job(job, "completed", {"completedDiscoveryAddresses": 1})
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=path))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        listing = await client.get("/api/v1/discovery-jobs")
        assert listing.status_code == 200
        assert listing.json()["items"][0]["id"] == job
        assert "nextCursor" in listing.json()
        detail = (await client.get(f"/api/v1/discovery-jobs/{job}")).json()
        assert "configSnapshot" in detail
        assert "startedAt" in detail
        assert detail["state"] == "completed"
        assert (await client.get(f"/api/v1/discovery-jobs/{job}/hosts")).json()["items"] == []
        assert (await client.get(f"/api/v1/discovery-jobs/{job}/probes?limit=201")).status_code == 422
        assert (await client.post("/api/v1/discovery-jobs", json={})).status_code == 401
        missing = await client.get("/api/v1/discovery-jobs/not-a-job")
        assert missing.status_code == 404
        assert missing.json()["code"] == "job_not_found"
        assert missing.json()["requestId"]


async def test_database_unavailable_is_503_not_empty_success(tmp_path):
    path = tmp_path / "not-created.sqlite"
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=path))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/discovery-jobs")
        assert response.status_code == 503
        assert response.json()["code"] == "database_unavailable"
        assert not path.exists()
        assert (await client.get("/health/live")).json() == {"status": "alive"}
