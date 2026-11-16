"""Invented fixtures / loopback only; never use the working inventory database."""
import asyncio
import json

import httpx
import pytest

from app.discovery.config import ScanSettings
from legacy_native.probes import LegacySystemProbes as SystemProbes
from legacy_native.runner import run_discovery
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult
from app.main import create_app


@pytest.fixture
def anyio_backend():
    return "asyncio"


class InventoryProbes:
    async def icmp(self, address):
        return ProbeResult(address, "icmp", "no_response")

    async def arp(self, address):
        return ProbeResult(address, "arp", "not_applicable")

    async def name(self, address):
        return ProbeResult(address, "name", "resolved", evidence={
            "hostname": "inventory-host.test", "source": "system_reverse_lookup",
        })

    async def tcp(self, address, port):
        return ProbeResult(address, "tcp", "open" if port in (22, 8080) else "timeout", port=port)

    async def banner(self, address, port):
        return ProbeResult(address, "banner", "received", port=port,
                           evidence={"banner": "SSH-2.0-OpenSSH_9.6p1\r\n"})

    async def http(self, address, port, https=False):
        return ProbeResult(address, "http", "response", port=port, evidence={
            "scheme": "http", "url": f"http://{address}:{port}/", "statusCode": 503,
            "title": "Inventory maintenance", "headers": {"server": "nginx/1.26.2"},
            "requestMethod": "GET", "followedRedirect": False,
        })


@pytest.mark.anyio
async def test_unresponsive_discovery_does_not_skip_configured_ssh_port(tmp_path):
    settings = ScanSettings(name="no-gating", targets=["10.5.8.12"], ports=[22, 80, 445],
                            discovery_ports=[80, 445], banner_ports=[22])
    db = initialize_database(tmp_path / "isolated.sqlite")
    job = await run_discovery(settings, db, InventoryProbes())
    hosts = db.list_hosts(job)["items"]
    assert len(hosts) == 1
    assert hosts[0]["open_ports"] == [22]
    coverage = db.get_job(job)["coverage"]
    assert coverage["completedTcpChecks"] == coverage["expectedTcpChecks"] == 3


@pytest.mark.anyio
async def test_saved_inventory_api_and_report_expose_names_services_websites(tmp_path):
    from app.discovery.report import write_report
    settings = ScanSettings(name="inventory", targets=["10.5.8.12"], ports=[22, 8080, 8443],
                            discovery_ports=[22], banner_ports=[22], http_ports=[8080])
    db = initialize_database(tmp_path / "isolated.sqlite")
    job = await run_discovery(settings, db, InventoryProbes())
    host = db.list_hosts(job)["items"][0]
    assert host["hostname"] == "inventory-host.test"
    assert host["hostname_source"] == "system_reverse_lookup"
    assert host["mac"] is None
    assert host["mac_status"] == "not_applicable"
    assert host["port_scan"]["attempted"] == 3
    assert host["port_scan"]["timeout"] == 1
    assert host["port_scan"]["complete"] is True
    ssh = next(row for row in host["services"] if row["port"] == 22)
    assert (ssh["protocol"], ssh["product"], ssh["version"]) == ("ssh", "OpenSSH", "9.6p1")
    website = host["websites"][0]
    assert website["status_code"] == 503
    assert website["title"] == "Inventory maintenance"
    assert website["screenshot"]["status"] == "not_requested"
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/api/v1/discovery-jobs/{job}/hosts")
        assert response.status_code == 200
        view = response.json()["items"][0]
        assert view["hostnameSource"] == "system_reverse_lookup"
        assert view["websites"][0]["statusCode"] == 503
    exported = write_report(db, job, tmp_path / "exports")
    text = (exported / "report.md").read_text(encoding="utf-8")
    assert "inventory-host.test" in text and "OpenSSH" in text
    assert "Inventory maintenance" in text
@pytest.mark.anyio
async def test_port_number_alone_never_confirms_a_service(tmp_path):
    class Unknown(InventoryProbes):
        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "open", port=port)

        async def banner(self, address, port):
            return ProbeResult(address, "banner", "empty", port=port)

    settings = ScanSettings(name="unknown", targets=["10.5.8.12"], ports=[3306],
                            discovery_ports=[3306], banner_ports=[3306])
    db = initialize_database(tmp_path / "isolated.sqlite")
    job = await run_discovery(settings, db, Unknown())
    service = db.list_hosts(job)["items"][0]["services"][0]
    assert service["protocol"] is None
    assert service["identification"] == "unknown"
    assert service["port_hint"] == "mysql"


@pytest.mark.anyio
async def test_http_title_is_bounded_no_cookie_retained_and_redirect_not_followed():
    settings = ScanSettings(name="http", targets=["10.5.8.12"], ports=[8080], http_ports=[8080])
    probes = SystemProbes(settings)
    await probes.client.aclose()
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8",
                                           "set-cookie": "secret", "server": "nginx"},
                              content=b"<html><title>Ops &amp; Inventory</title></html>")

    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await probes.http("10.5.8.12", 8080)
        assert result.evidence["title"] == "Ops & Inventory"
        assert result.evidence["requestMethod"] == "GET"
        assert "secret" not in json.dumps(result.evidence)
        assert requests[0].method == "GET"
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_name_lookup_preserves_source_and_failure_without_inventing_names(monkeypatch):
    import socket
    settings = ScanSettings(name="names", targets=["10.5.8.12"], ports=[22])
    probes = SystemProbes(settings)
    monkeypatch.setattr(socket, "gethostbyaddr",
                        lambda address: ("host.test", [], [address]))
    try:
        result = await probes.name("10.5.8.12")
        assert result.status == "resolved"
        assert result.evidence["hostname"] == "host.test"
        assert result.evidence["source"] == "system_reverse_lookup"
        with pytest.raises(ValueError, match="scope"):
            await probes.name("10.5.9.12")
    finally:
        await probes.close()


def test_all_tcp_ports_is_explicit_not_the_default():
    common = ScanSettings(name="common", targets=["10.5.8.12"], ports=[22, 80])
    assert list(common.effective_ports()) == [22, 80]
    thorough = ScanSettings(name="all", targets=["10.5.8.12"], ports=[22], tcp_port_mode="all")
    ports = thorough.effective_ports()
    assert len(ports) == 65535 and ports[0] == 1 and ports[-1] == 65535
    full_web = ScanSettings(name="all-web", targets=["10.5.8.12"], ports=[22],
                            tcp_port_mode="all", http_ports=[8080])
    assert 8080 in full_web.effective_ports()


@pytest.mark.anyio
async def test_nonstandard_open_port_gets_passive_service_detection(tmp_path):
    class Nonstandard(InventoryProbes):
        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "open", port=port)

    settings = ScanSettings(name="nonstandard", targets=["10.5.8.12"], ports=[2222],
                            discovery_ports=[2222])
    db = initialize_database(tmp_path / "isolated.sqlite")
    job = await run_discovery(settings, db, Nonstandard())
    service = db.list_hosts(job)["items"][0]["services"][0]
    assert service["protocol"] == "ssh"
    assert service["port"] == 2222 and service["port_hint"] is None


@pytest.mark.anyio
async def test_mysql_greeting_is_identified_without_login_or_client_payload():
    received = []
    disconnected = asyncio.Event()

    async def handle(reader, writer):
        greeting = b"\x0a8.4.0-test\x00" + b"\x01\x00\x00\x00" + b"abcdefgh\x00" + b"\xff\xff"
        writer.write(len(greeting).to_bytes(3, "little") + b"\x00" + greeting)
        await writer.drain()
        received.append(await reader.read(1))
        disconnected.set()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    probes = SystemProbes(ScanSettings(name="mysql", targets=["127.0.0.1"], ports=[port],
                                      allow_loopback=True))
    try:
        result = await probes.banner("127.0.0.1", port)
        assert result.evidence["protocol"] == "mysql"
        assert result.evidence["version"] == "8.4.0-test"
        await asyncio.wait_for(disconnected.wait(), 1)
        assert received == [b""]
    finally:
        await probes.close()
        server.close()
        await server.wait_closed()


def test_nbstat_parser_rejects_group_names_mismatched_transactions_and_short_packets():
    import struct
    from app.discovery.names import parse_nbstat
    transaction = 1234
    group = b"WORKGROUP".ljust(15, b" ") + b"\x00\x80\x00"
    host = b"INVENTORY-PC".ljust(15, b" ") + b"\x00\x00\x00"
    payload = b"\x02" + group + host
    packet = (struct.pack("!6H", transaction, 0x8400, 0, 1, 0, 0)
              + b"\x00" + struct.pack("!HHIH", 0x21, 1, 0, len(payload)) + payload)
    assert parse_nbstat(packet, transaction) == "INVENTORY-PC"
    assert parse_nbstat(packet, transaction + 1) is None
    assert parse_nbstat(packet[:-10], transaction) is None


@pytest.mark.anyio
async def test_screenshot_artifact_ids_and_render_stats_do_not_create_false_history_changes(tmp_path):
    from app.discovery.report import compare_snapshot
    settings = ScanSettings(name="history", targets=["10.5.8.12"], ports=[8080])
    db = initialize_database(tmp_path / "isolated.sqlite")
    scope, revision = db.save_scope(settings)
    for number in range(2):
        job = db.begin_job(scope, revision, settings.snapshot())
        db.record_probes(job, [ProbeResult(
            "10.5.8.12", "screenshot", "captured", port=8080, phase="enrichment",
            evidence={"scheme": "http", "file": f"{number:032x}.png", "bytesCollected": 100 + number,
                      "renderMode": "static_no_javascript"})])
        db.finish_job(job, "completed", {})
    comparison = compare_snapshot(db.scan_snapshot(job))
    assert comparison["status"] == "available"
    assert comparison["probe_changes"] == []


@pytest.mark.anyio
async def test_http_capture_never_sends_a_cookie_from_an_earlier_asset():
    probes = SystemProbes(ScanSettings(name="cookies", targets=["10.5.8.12"], ports=[8080]))
    await probes.client.aclose()
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"set-cookie": "session=secret; Path=/",
                                           "content-type": "text/html"},
                              content=b"<title>Local</title>")

    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        await probes.http("10.5.8.12", 8080)
        await probes.http("10.5.8.12", 8080)
        assert all(not request.headers.get("cookie") for request in requests)
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_partial_scan_preserves_early_name_and_service_evidence(tmp_path):
    class SlowTail(InventoryProbes):
        async def icmp(self, address):
            return ProbeResult(address, "icmp", "reply")

        async def tcp(self, address, port):
            if address.endswith(".11"):
                await asyncio.sleep(1)
            return ProbeResult(address, "tcp", "open", port=port)

    settings = ScanSettings(name="partial-evidence", targets=["10.5.8.10-10.5.8.11"],
                            ports=[22], banner_ports=[22], concurrency=1, budget_seconds=0.15)
    db = initialize_database(tmp_path / "isolated.sqlite")
    job = await run_discovery(settings, db, SlowTail())
    assert db.get_job(job)["state"] == "partial"
    host = next(host for host in db.list_hosts(job)["items"] if host["address"].endswith(".10"))
    assert host["hostname"] == "inventory-host.test"
    assert host["services"][0]["protocol"] == "ssh"
    assert host["port_scan"]["complete"] is True


@pytest.mark.anyio
async def test_invalid_charset_and_large_html_cannot_break_http_observation():
    probes = SystemProbes(ScanSettings(name="large", targets=["10.5.8.12"], ports=[8080],
                                      http_body_limit=1024))
    await probes.client.aclose()
    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "text/html; charset=not-a-real-encoding"},
        content=b"<title>Bounded title</title>" + b"x" * 10000)))
    try:
        result = await probes.http("10.5.8.12", 8080)
        assert result.status == "response"
        assert result.evidence["title"] == "Bounded title"
        assert result.evidence["bodyBytesRead"] == 1024
        assert result.evidence["bodyTruncated"] is True
        assert "xxxx" not in json.dumps(result.evidence)
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_system_probe_rejects_ports_outside_configured_authorization(monkeypatch):
    probes = SystemProbes(ScanSettings(name="port-guard", targets=["10.5.8.12"], ports=[22]))
    def forbidden_network(*args, **kwargs):
        raise AssertionError("Out-of-scope request reached the transport")
    monkeypatch.setattr(probes, "_open", forbidden_network)
    monkeypatch.setattr(probes.client, "stream", forbidden_network)
    try:
        with pytest.raises(ValueError, match="scope"):
            await probes.tcp("10.5.8.12", 23)
        with pytest.raises(ValueError, match="scope"):
            await probes.http("10.5.8.12", 8080)
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_unavailable_name_remains_missing_not_an_ip_based_placeholder(monkeypatch):
    import socket
    settings = ScanSettings(name="no-name", targets=["10.5.8.12"], ports=[22], netbios_enabled=False)
    probes = SystemProbes(settings)

    def unavailable(address):
        raise socket.herror("No name")

    monkeypatch.setattr(socket, "gethostbyaddr", unavailable)
    try:
        result = await probes.name("10.5.8.12")
        assert result.status == "no_response"
        assert "hostname" not in result.evidence
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_multilingual_evidence_preserves_structured_fields_under_storage_limit():
    from app.discovery.types import bounded_evidence
    probes = SystemProbes(ScanSettings(name="unicode", targets=["10.5.8.12"], ports=[8080]))
    await probes.client.aclose()
    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
        200, headers=[(b"content-type", b"text/html; charset=utf-8"),
                      (b"server", ("服" * 200).encode()),
                      (b"allow", ("读" * 200).encode()),
                      (b"location", ("/" + "站" * 300).encode())],
        content=("<title>" + "网" * 300 + "</title>").encode())))
    try:
        result = await probes.http("10.5.8.12", 8080)
        stored = bounded_evidence(result.evidence)
        assert stored["statusCode"] == 200
        assert stored["scheme"] == "http" and stored["title"].startswith("网")
        assert len(json.dumps(stored, ensure_ascii=False, separators=(",", ":")).encode()) <= 2048
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_compressed_html_is_not_expanded_outside_the_body_budget():
    import gzip
    probes = SystemProbes(ScanSettings(name="encoded", targets=["10.5.8.12"], ports=[8080]))
    await probes.client.aclose()
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html", "content-encoding": "gzip"},
                              stream=httpx.ByteStream(gzip.compress(b"<title>Compressed</title>")))

    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        result = await probes.http("10.5.8.12", 8080)
        assert result.status == "response"
        assert result.evidence["title"] is None
        assert result.evidence["bodySkippedReason"] == "unsupported_content_encoding"
        assert requests[0].headers["accept-encoding"] == "identity"
    finally:
        await probes.close()


@pytest.mark.anyio
async def test_https_internal_failure_keeps_requested_scheme(tmp_path):
    class BrokenHttp(InventoryProbes):
        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "open", port=port)

        async def http(self, address, port, https=False):
            raise RuntimeError("Isolated transport failure")

    db = initialize_database(tmp_path / "isolated.sqlite")
    settings = ScanSettings(name="https-failure", targets=["10.5.8.12"], ports=[443], https_ports=[443])
    job = await run_discovery(settings, db, BrokenHttp())
    site = db.list_hosts(job)["items"][0]["websites"][0]
    assert site["url"] == "https://10.5.8.12:443/"
    assert site["status"] == "error"


def test_enabled_but_interrupted_screenshot_is_not_reported_as_disabled(tmp_path):
    db = initialize_database(tmp_path / "isolated.sqlite")
    settings = ScanSettings(name="interrupted-shot", targets=["10.5.8.12"], ports=[8080],
                            http_ports=[8080], screenshots_enabled=True)
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    db.record_discovery(job, "10.5.8.12", [], {
        "mac": None, "discovery_methods": ["tcp:open"], "confidence": "direct_response", "context": {},
    })
    db.record_probes(job, [
        ProbeResult("10.5.8.12", "tcp", "open", port=8080, phase="inventory"),
        ProbeResult("10.5.8.12", "http", "response", port=8080, phase="enrichment",
                    evidence={"scheme": "http", "statusCode": 200}),
    ])
    db.finish_job(job, "partial", {}, "budget_exceeded")
    shot = db.list_hosts(job)["items"][0]["websites"][0]["screenshot"]
    assert shot["status"] == "not_collected"
    assert shot["reason_code"] == "screenshot_not_completed"
