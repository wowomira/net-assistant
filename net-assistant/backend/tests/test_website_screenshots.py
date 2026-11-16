import asyncio
import importlib.util
import json
import socket
from uuid import uuid4

import httpx
import pytest

from app.discovery.config import ScanSettings
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult
from app.main import create_app


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_capture_scope_rejects_domains_other_ports_credentials_and_other_addresses(tmp_path):
    from app.discovery.screenshots import ScreenshotCollector
    settings = ScanSettings(name="shots", targets=["10.5.8.12"], ports=[8080])
    collector = ScreenshotCollector(settings, tmp_path)
    origin = "http://10.5.8.12:8080/"
    assert collector.permits_resource(origin + "style.css", origin)
    for url in ["http://example.test:8080/", "http://10.5.8.13:8080/",
                "http://10.5.8.12:22/", "http://10.5.8.12:0/", "file:///C:/Windows/win.ini",
                "http://user:pass@10.5.8.12:8080/", "https://10.5.8.12:8080/"]:
        assert not collector.permits_resource(url, origin)


@pytest.mark.anyio
async def test_missing_browser_dependency_is_explicit_not_a_fake_capture(tmp_path, monkeypatch):
    from app.discovery.screenshots import ScreenshotCollector
    collector = ScreenshotCollector(ScanSettings(name="shots", targets=["10.5.8.12"], ports=[8080]),
                                    tmp_path)
    monkeypatch.setattr(collector, "_playwright", lambda: None)
    result = await collector.capture("10.5.8.12", 8080)
    assert result.status == "not_supported"
    assert result.reason_code == "screenshot_dependency_missing"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.anyio
async def test_capture_endpoint_serves_only_the_recorded_png_not_arbitrary_files(tmp_path):
    path = tmp_path / "isolated.sqlite"
    db = initialize_database(path)
    settings = ScanSettings(name="shots", targets=["10.5.8.12"], ports=[8080])
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    filename = uuid4().hex + ".png"
    directory = tmp_path / "artifacts" / "screenshots"
    directory.mkdir(parents=True)
    png = b"\x89PNG\r\n\x1a\n" + b"test-fixture"
    (directory / filename).write_bytes(png)
    db.record_probes(job, [ProbeResult("10.5.8.12", "screenshot", "captured", port=8080,
                                     phase="enrichment", evidence={"file": filename, "scheme": "http"})])
    probe = db.list_probes(job)["items"][0]["id"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=path)),
                                base_url="http://testserver") as client:
        response = await client.get(f"/api/v1/discovery-jobs/{job}/screenshots/{probe}")
        assert response.status_code == 200
        assert response.content == png and response.headers["content-type"] == "image/png"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert (await client.get(f"/api/v1/discovery-jobs/{uuid4()}/screenshots/{probe}")).status_code == 404
        (directory / filename).unlink()
        assert (await client.get(f"/api/v1/discovery-jobs/{job}/screenshots/{probe}")).status_code == 404


@pytest.mark.anyio
async def test_real_browser_capture_blocks_outside_origin_scripts_and_redirects(tmp_path):
    if importlib.util.find_spec("playwright") is None:
        pytest.skip("Optional screenshot dependency not installed; run with isolated screenshot test deps.")
    from app.discovery.screenshots import ScreenshotCollector
    external_hits = []

    async def external(reader, writer):
        external_hits.append(await reader.read(4096))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    outside = await asyncio.start_server(external, "127.0.0.1", 0)
    outside_port = outside.sockets[0].getsockname()[1]
    requests = []

    async def website(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        requests.append(data)
        body = (f"<html><head><title>Isolated capture</title></head><body>"
                f"<h1>Local website</h1><img src='http://127.0.0.1:{outside_port}/secret'>"
                f"<script>fetch('http://127.0.0.1:{outside_port}/script')</script></body></html>").encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(website, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    collector = ScreenshotCollector(ScanSettings(
        name="local-shots", targets=["127.0.0.1"], ports=[port], allow_loopback=True,
        screenshots_enabled=True, screenshot_timeout_ms=10000,
    ), tmp_path)
    try:
        result = await collector.capture("127.0.0.1", port)
        assert result.status == "captured", (result.status, result.reason_code, result.evidence)
        image = tmp_path / result.evidence["file"]
        assert image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert external_hits == []
        assert len(requests) == 1
        assert result.evidence["javascriptEnabled"] is False
        assert result.evidence["blockedRequests"] >= 1
        assert result.evidence["renderIncomplete"] is True
    finally:
        await collector.close()
        server.close()
        outside.close()
        await server.wait_closed()
        await outside.wait_closed()


@pytest.mark.anyio
async def test_real_screenshot_redirect_does_not_contact_destination(tmp_path):
    if importlib.util.find_spec("playwright") is None:
        pytest.skip("Optional screenshot dependency not installed.")
    from app.discovery.screenshots import ScreenshotCollector
    hits = []

    async def handler(reader, writer):
        hits.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/forbidden\r\n"
                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    collector = ScreenshotCollector(ScanSettings(name="redirect", targets=["127.0.0.1"],
                                                ports=[port], allow_loopback=True), tmp_path)
    try:
        result = await collector.capture("127.0.0.1", port)
        assert result.status == "blocked"
        assert result.reason_code == "screenshot_redirect_not_followed"
        assert len(hits) == 1 and list(tmp_path.glob("*.png")) == []
    finally:
        await collector.close()
        server.close()
        await server.wait_closed()
