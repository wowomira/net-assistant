"""Independent invented observations; no real machines or database are modified."""
import asyncio
import sqlite3

import httpx
import pytest

from app.assets.service import AssetRegistry
from app.discovery.config import ScanSettings
from legacy_native.runner import run_discovery
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult
from app.main import create_app


def make_job(db, hosts, name="identity-lab", state="completed"):
    settings = ScanSettings(name=name, targets=["10.17.0.0/24"], ports=[80])
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    for address, mac, confidence in hosts:
        db.record_discovery(job, address, [ProbeResult(address, "icmp", "reply")], {
            "mac": mac, "confidence": confidence, "discovery_methods": ["icmp:reply"], "context": {},
        })
    if state != "running":
        db.finish_job(job, state, {})
    return job


def auto(db, job):
    from app.assets.automatic import reconcile_job
    return reconcile_job(db, job)


@pytest.fixture
def db(tmp_path):
    return initialize_database(tmp_path / "independent.sqlite")


def test_new_device_automatically_registers_and_changed_ip_keeps_uuid(db):
    first = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    assert auto(db, first)["registered"] == 1
    registry = AssetRegistry(db)
    original = registry.list_assets()["items"][0]
    assert original["registration_source"] == "automatic"
    assert original["management_status"] == "discovered"
    assert original["collection_access"] == "not_enrolled"
    assert original["host_metrics"] is None
    second = make_job(db, [("10.17.0.90", "00-11-22-33-44-55", "direct_response")])
    assert auto(db, second)["linked"] == 1
    assets = registry.list_assets()["items"]
    assert len(assets) == 1
    assert assets[0]["id"] == original["id"]
    assert assets[0]["identity_status"] == "mac_correlated"
    assert {r["address"] for r in registry.list_observations(original["id"])["items"]} == {
        "10.17.0.10", "10.17.0.90"}
    events = registry.list_audit(original["id"])["items"]
    assert [event["actor"] for event in events] == ["automatic_discovery", "automatic_discovery"]
    assert events[1]["details"]["rule"] == "unique_mac_same_scope"


def test_same_ip_new_mac_is_separate_and_across_scope_never_merges(db):
    first = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    auto(db, first)
    second = make_job(db, [("10.17.0.10", "00:11:22:33:44:66", "direct_response")])
    auto(db, second)
    third = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")], name="another-network")
    auto(db, third)
    assets = AssetRegistry(db).list_assets()["items"]
    assert len(assets) == len({a["id"] for a in assets}) == 3


@pytest.mark.parametrize("mac", [None, "invalid", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"])
def test_missing_or_invalid_mac_creates_review_record_not_ip_identity(db, mac):
    one = make_job(db, [("10.17.0.10", mac, "direct_response")])
    two = make_job(db, [("10.17.0.10", mac, "direct_response")])
    auto(db, one)
    auto(db, two)
    assets = AssetRegistry(db).list_assets()["items"]
    assert len(assets) == 2
    assert all(a["identity_status"] == "needs_review" for a in assets)


def test_duplicate_mac_in_single_scan_never_merges(db):
    mac = "00:11:22:33:44:55"
    before = make_job(db, [("10.17.0.10", mac, "direct_response")])
    auto(db, before)
    collision = make_job(db, [
        ("10.17.0.11", mac, "direct_response"), ("10.17.0.12", mac, "direct_response")])
    result = auto(db, collision)
    assert result["registered"] == 2 and result["linked"] == 0
    assets = AssetRegistry(db).list_assets()["items"]
    assert len(assets) == 3
    assert all(a["identity_status"] == "needs_review" for a in assets[1:])
    later = make_job(db, [("10.17.0.20", mac, "direct_response")])
    assert auto(db, later)["linked"] == 0
    assert AssetRegistry(db).list_assets()["items"][-1]["identity_status"] == "needs_review"


def test_existing_manual_asset_reused_without_renaming_or_granting_access(db):
    first = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    host = db.list_hosts(first)["items"][0]["id"]
    registry = AssetRegistry(db)
    old = registry.register(host, name="My explicit name", reason="Owner confirmed", owner="team")
    assert auto(db, first)["existing"] == 1
    second = make_job(db, [("10.17.0.20", "00:11:22:33:44:55", "direct_response")])
    assert auto(db, second)["linked"] == 1
    current = registry.get_asset(old["id"])
    assert current["name"] == "My explicit name" and current["owner"] == "team"
    assert current["management_status"] == "managed"
    assert current["collection_access"] == "not_enrolled"


def test_repeated_processing_and_manual_unlink_do_not_silently_rebind(db):
    job = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    auto(db, job)
    assert auto(db, job)["already_processed"] == 1
    registry = AssetRegistry(db)
    asset = registry.list_assets()["items"][0]
    host = db.list_hosts(job)["items"][0]["id"]
    registry.unlink(asset["id"], host, expected_revision=1, reason="Incorrect identity association")
    auto(db, job)
    assert registry.get_asset(asset["id"])["linked_observation_count"] == 0
    assert len(registry.list_audit(asset["id"])["items"]) == 2


@pytest.mark.parametrize("state", ["running", "failed", "interrupted"])
def test_incomplete_scan_does_not_create_assets(db, state):
    job = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")], state=state)
    with pytest.raises(ValueError, match="completed|partial"):
        auto(db, job)
    assert AssetRegistry(db).list_assets()["items"] == []


def test_candidate_only_does_not_register_but_partial_direct_response_does(db):
    job = make_job(db, [
        ("10.17.0.10", "00:11:22:33:44:55", "candidate_only"),
        ("10.17.0.11", "00:11:22:33:44:66", "direct_response")], state="partial")
    result = auto(db, job)
    assert result["skipped"] == 1 and result["registered"] == 1


def test_audit_write_failure_rolls_back_asset_link_and_decision(db):
    job = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    with sqlite3.connect(db.path) as connection:
        connection.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON asset_audit_events "
                           "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END")
    with pytest.raises(Exception, match="injected audit failure"):
        auto(db, job)
    assert AssetRegistry(db).list_assets()["items"] == []
    with sqlite3.connect(db.path) as connection:
        assert connection.execute("SELECT count(*) FROM asset_identity_decisions").fetchone()[0] == 0


def test_runner_itself_registers_and_http_reads_automatic_actor(db):
    class Probes:
        async def icmp(self, address):
            return ProbeResult(address, "icmp", "reply")

        async def arp(self, address):
            return ProbeResult(address, "arp", "resolved", evidence={"mac": "00:11:22:33:44:55"})

        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "open", port=port)

    settings = ScanSettings(name="scan-integration", targets=["10.17.0.10"], ports=[80])
    job = asyncio.run(run_discovery(settings, db, Probes()))
    host = db.list_hosts(job)["items"][0]
    assert host["asset_id"] is not None
    assert db.get_job(job)["coverage"]["assetRegistration"]["registered"] == 1
    assert db.get_job(job)["trigger"] == "manual"

    async def check_http():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)),
                                    base_url="http://test") as client:
            response = await client.get(f"/api/v1/assets/{host['asset_id']}")
            assert response.status_code == 200
            assert response.json()["registrationSource"] == "automatic"
            assert response.json()["managementStatus"] == "discovered"
            assert response.json()["identityVerified"] is False
            audit = await client.get(f"/api/v1/assets/{host['asset_id']}/audit")
            assert audit.status_code == 200
            assert audit.json()["items"][0]["actor"] == "automatic_discovery"
            association = await client.get(f"/api/v1/discovery-hosts/{host['id']}/asset-association")
            assert association.json()["automaticDecision"]["rule"] == "new_mac"
            assert association.json()["automaticDecision"]["assetId"] == host["asset_id"]
            assert association.json()["automaticDecision"]["decidedAt"].endswith("Z")

    asyncio.run(check_http())


def test_concurrent_reconciliation_creates_only_one_asset_and_one_audit(db):
    from concurrent.futures import ThreadPoolExecutor
    job = make_job(db, [("10.17.0.10", "00:11:22:33:44:55", "direct_response")])
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: auto(db, job), range(2)))
    assert sum(result["registered"] for result in results) == 1
    assets = AssetRegistry(db).list_assets()["items"]
    assert len(assets) == 1
    assert len(AssetRegistry(db).list_audit(assets[0]["id"])["items"]) == 1


def test_registration_failure_in_runner_keeps_raw_results_and_reports_partial(db, monkeypatch):
    class Probes:
        async def icmp(self, address):
            return ProbeResult(address, "icmp", "reply")

        async def tcp(self, address, port):
            return ProbeResult(address, "tcp", "timeout", port=port)

    def fail(*args):
        raise OSError("test storage fault")

    monkeypatch.setattr("app.assets.automatic.reconcile_job", fail)
    settings = ScanSettings(name="asset-storage-error", targets=["10.17.0.10"], ports=[80], arp_enabled=False)
    job = asyncio.run(run_discovery(settings, db, Probes()))
    assert db.get_job(job)["state"] == "partial"
    assert db.get_job(job)["error_code"] == "asset_registration_failed"
    assert db.list_hosts(job)["items"]
    assert db.list_probes(job)["items"]
