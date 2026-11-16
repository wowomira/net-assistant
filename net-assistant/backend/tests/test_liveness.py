"""Milestone 1: liveness is not inspection readiness or target health."""

import httpx
import pytest

from app.main import create_app


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, ))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


async def test_liveness_reports_only_process_alive(client):
    response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert response.headers["content-type"] == "application/json"


async def test_liveness_response_is_not_cached(client):
    response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


async def test_openapi_declares_typed_liveness_contract(client):
    schema = (await client.get("/openapi.json")).json()

    assert "/health/live" in schema["paths"]
    operation = schema["paths"]["/health/live"]["get"]
    assert operation["operationId"] == "getLiveness"
    body_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert body_schema["$ref"] == "#/components/schemas/LivenessResponse"
    status = schema["components"]["schemas"]["LivenessResponse"]["properties"]["status"]
    assert status["const"] == "alive"
    assert "/health/ready" not in schema["paths"]


async def test_unimplemented_readiness_does_not_claim_success(client):
    assert (await client.get("/health/ready")).status_code == 404


async def test_guide_progress_service_is_not_part_of_this_application(client):
    assert (await client.get("/api/progress")).status_code == 404


async def test_liveness_rejects_post(client):
    assert (await client.post("/health/live")).status_code == 405
