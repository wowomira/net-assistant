import asyncio
import json
import ssl
import socket
import struct
import ctypes
from unittest.mock import MagicMock

import httpx
import pytest

from app.discovery.config import ROOT, ScanSettings, load_settings
from legacy_native.probes import LegacySystemProbes as SystemProbes
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult, bounded_evidence

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_profile_covers_major_categories_without_claiming_all_ports():
    settings = load_settings(ROOT / "configs/scope.example.json")
    assert len(settings.ports) >= 100
    assert {22, 80, 443, 135, 139, 445, 3389, 5985, 5986, 3306, 5432,
            6379, 8080, 9200, 27017}.issubset(settings.ports)
    assert 9100 not in settings.http_ports  # Do not send an HTTP request to a raw printer port.
    assert set(settings.ports) != set(range(1, 65536))


def test_evidence_bound_is_utf8_bytes_not_character_count():
    evidence = bounded_evidence({"banner": "测" * 10000})
    assert len(json.dumps(evidence, ensure_ascii=False).encode()) <= 2048


async def test_tcp_and_passive_banner_against_real_loopback_service():
    async def handle(reader, writer):
        writer.write(b"SSH-2.0-local-test\r\n")
        await writer.drain()
        await reader.read(1)  # The collector must not send application/login data.
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    settings = ScanSettings(
        name="local", targets=["127.0.0.1"], ports=[port], discovery_ports=[port],
        source_address="127.0.0.1", allow_loopback=True, arp_enabled=False,
    )
    probes = SystemProbes(settings, "127.0.0.0/8")
    try:
        assert (await probes.tcp("127.0.0.1", port)).status == "open"
        banner = await probes.banner("127.0.0.1", port)
        assert banner.status == "received"
        assert banner.evidence["sentApplicationData"] is False
        assert banner.evidence["banner"].startswith("SSH-2.0-local-test")
        with pytest.raises(ValueError, match="scope"):
            await probes.tcp("10.0.0.1", port)
    finally:
        await probes.close()
        server.close()
        await server.wait_closed()


async def test_http_does_not_follow_redirect_or_store_sensitive_headers():
    settings = ScanSettings(name="headers", targets=["10.8.9.10"], ports=[80],
                            discovery_ports=[80], http_ports=[80])
    probes = SystemProbes(settings)
    await probes.client.aclose()
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={
            "server": "test-server", "set-cookie": "do-not-store",
            "authorization": "do-not-store", "location": "http://10.99.99.99/secret",
        })

    probes.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await probes.http("10.8.9.10", 80)
        assert len(requests) == 1
        assert requests[0].method == "GET"
        assert result.evidence["statusCode"] == 302
        assert result.evidence["bodyCollected"] is False
        assert result.evidence["headers"] == {"server": "test-server"}
        assert result.evidence["redirectLocation"] == "http://10.99.99.99/secret"
        assert "do-not-store" not in json.dumps(result.evidence)
    finally:
        await probes.close()


async def test_tls_keeps_verification_and_reports_certificate_errors(monkeypatch):
    settings = ScanSettings(name="tls", targets=["10.8.9.10"], ports=[443])
    probes = SystemProbes(settings)
    checked = []

    async def fail_handshake(address, port, **kwargs):
        checked.append(kwargs)
        error = ssl.SSLCertVerificationError(1, "untrusted test certificate")
        error.verify_code = 18
        raise error

    monkeypatch.setattr(probes, "_open", fail_handshake)
    try:
        result = await probes.tls("10.8.9.10", 443)
        assert checked[0]["ssl"].verify_mode == ssl.CERT_REQUIRED
        assert checked[0]["ssl"].check_hostname is True
        assert result.status == "certificate_error"
        assert result.evidence["verification"] == "failed"
    finally:
        await probes.close()


def test_context_ownership_labels_never_grant_host_collection(tmp_path):
    db = initialize_database(tmp_path / "test.sqlite")
    settings = ScanSettings(name="test", targets=["10.1.1.1"], ports=[80])
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    db.record_discovery(job, "10.1.1.1", [ProbeResult("10.1.1.1", "icmp", "reply")], {
        "mac": None, "discovery_methods": ["icmp:reply"], "confidence": "direct_response",
        "context": {"displayName": "my-authorized-server", "collectionAuthorization": True},
    })
    host = db.list_hosts(job)["items"][0]
    assert host["management_status"] == "discovered"
    assert host["collection_access"] == "not_enrolled"
    assert host["asset_kind"] == "unknown"


async def test_native_icmp_binds_explicit_source_and_closes_handle(monkeypatch):
    settings = ScanSettings(name="source", targets=["10.8.9.10"], ports=[80],
                            source_address="10.8.9.1")
    probes = SystemProbes(settings)
    api = MagicMock()
    api.IcmpCreateFile.return_value = 123
    api.IcmpSendEcho.return_value = 0
    called = []

    def echo(*args):
        called.append(args)
        ctypes.memmove(args[9], struct.pack("=III", args[5], 0, 2), 12)
        return 1

    api.IcmpSendEcho2Ex.side_effect = echo
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: api)
    try:
        result = probes._icmp_windows("10.8.9.10")
        assert result.status == "reply"
        assert called[0][4] == struct.unpack("=I", socket.inet_aton("10.8.9.1"))[0]
        assert called[0][5] == struct.unpack("=I", socket.inet_aton("10.8.9.10"))[0]
        api.IcmpCloseHandle.assert_called_once_with(123)
    finally:
        await probes.close()
