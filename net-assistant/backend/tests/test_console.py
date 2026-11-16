"""Read-only console delivery must never expose the project or swallow API errors."""

from pathlib import Path

import httpx
import pytest

from app.main import create_app

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_console_delivers_only_explicit_build_and_redirects_root(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Console test</title>", encoding="utf-8")
    (dist / "assets").mkdir()
    (dist / "assets" / "app.js").write_text("console.log('build')", encoding="utf-8")
    (tmp_path / "secret.sqlite").write_text("not public", encoding="utf-8")
    app = create_app(allow_anonymous_reads=True, database_path=tmp_path / "missing.sqlite", frontend_dist=dist)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://local") as client:
        assert (await client.get("/")).headers["location"] == "/console/"
        page = await client.get("/console/")
        assert page.status_code == 200
        assert "Console test" in page.text
        assert page.headers["cache-control"] == "no-cache"
        assert (await client.get("/console/assets/app.js")).status_code == 200
        for url in ("/console/secret.sqlite", "/console/%2e%2e/secret.sqlite",
                    "/console/src/App.tsx", "/api/progress", "/api/v1/no-such-api"):
            assert (await client.get(url)).status_code == 404
        assert (await client.post("/console/")).status_code == 405
        assert (await client.get("/api/v1/assets")).status_code == 503
    assert not (tmp_path / "missing.sqlite").exists()


async def test_missing_build_does_not_claim_console_available(tmp_path):
    app = create_app(allow_anonymous_reads=True, database_path=tmp_path / "missing.sqlite", frontend_dist=tmp_path / "no-build")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://local") as client:
        response = await client.get("/console/")
        assert response.status_code == 503
        assert "尚未构建" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert (await client.get("/health/live")).json() == {"status": "alive"}
