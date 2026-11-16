import asyncio

import pytest

from app.discovery.config import ScanSettings
from legacy_native.runner import run_discovery
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeProbes:
    def __init__(self):
        self.calls = []

    async def icmp(self, address):
        self.calls.append((address, "icmp"))
        return ProbeResult(address, "icmp", "reply" if address.endswith(".10") else "no_response")

    async def arp(self, address):
        self.calls.append((address, "arp"))
        return ProbeResult(address, "arp", "reply" if address.endswith(".11") else "no_response",
                           evidence={"mac": "00:11:22:33:44:55"} if address.endswith(".11") else {})

    async def tcp(self, address, port):
        self.calls.append((address, port))
        status = "open" if address.endswith(".10") and port == 22 else "timeout"
        return ProbeResult(address, "tcp", status, port=port)

    async def http(self, address, port, https=False):
        return ProbeResult(address, "http", "response", port=port, evidence={"statusCode": 200})

    async def tls(self, address, port):
        return ProbeResult(address, "tls", "certificate_error", port=port)

    async def banner(self, address, port):
        return ProbeResult(address, "banner", "received", port=port, evidence={"banner": "SSH-2.0-test"})


async def test_blocked_icmp_still_discovers_arp_host_and_all_configured_ports(tmp_path):
    settings = ScanSettings(
        name="fake", targets=["10.5.8.10-10.5.8.12"], ports=[22, 80],
        discovery_ports=[80], banner_ports=[22], concurrency=2,
    )
    db = initialize_database(tmp_path / "test.sqlite")
    probes = FakeProbes()
    job = await run_discovery(settings, db, probes)
    record = db.get_job(job)
    assert record["state"] == "completed"
    assert record["coverage"]["completedDiscoveryAddresses"] == 3
    assert record["coverage"]["responsiveHosts"] == 2
    # Every authorized address is inventoried, including the nonresponsive .12.
    assert record["coverage"]["completedTcpChecks"] == 6
    assert record["coverage"]["expectedTcpChecks"] == 6
    hosts = db.list_hosts(job)["items"]
    assert {host["address"] for host in hosts} == {"10.5.8.10", "10.5.8.11"}
    assert all(call[0] in settings.addresses() for call in probes.calls)
    evidence = db.list_probes(job, method="banner")["items"]
    assert evidence[0]["evidence"]["banner"] == "SSH-2.0-test"
    assert db.get_job(job)["config_snapshot"]["ports"] == [22, 80]


async def test_task_budget_preserves_partial_coverage(tmp_path):
    class SlowProbes(FakeProbes):
        async def icmp(self, address):
            await asyncio.sleep(1)
            return await super().icmp(address)

    settings = ScanSettings(
        name="deadline", targets=["10.5.8.10"], ports=[80], discovery_ports=[80],
        budget_seconds=0.05,
    )
    db = initialize_database(tmp_path / "test.sqlite")
    job = await run_discovery(settings, db, SlowProbes())
    result = db.get_job(job)
    assert result["state"] == "partial"
    assert result["coverage"]["completedDiscoveryAddresses"] == 0
    assert result["coverage"]["candidateAddresses"] == 1
    assert result["error_code"] == "budget_exceeded"


async def test_probe_internal_error_is_not_target_failure_or_false_healthy(tmp_path):
    class BrokenProbes(FakeProbes):
        async def icmp(self, address):
            raise RuntimeError("internal probe problem")

    settings = ScanSettings(
        name="error", targets=["10.5.8.12"], ports=[80], discovery_ports=[80],
    )
    db = initialize_database(tmp_path / "test.sqlite")
    job = await run_discovery(settings, db, BrokenProbes())
    results = db.list_probes(job)["items"]
    assert any(p["status"] == "error" and p["reason_code"] == "probe_internal_error" for p in results)
    assert db.list_hosts(job)["items"] == []
    assert db.get_job(job)["state"] == "partial"
