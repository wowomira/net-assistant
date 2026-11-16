"""Isolated databases only; fixtures are never written to the project work DB."""
from importlib.util import find_spec
import asyncio
from uuid import uuid4

import httpx
import pytest

from app.collectors.contracts import NetworkSnapshot
from app.discovery.store import Database, initialize_database
from app.main import create_app


def snapshot():
    return NetworkSnapshot.model_validate({
        "source": "windows_native", "observed_at": "2026-11-14T00:00:00Z",
        "interfaces": [{"interface_index": 7, "name": "test-only LAN",
                        "mac": "00:11:22:33:44:55", "state": "Up",
                        "addresses": [{"address": "10.0.0.2", "prefix_length": 24,
                                       "source": "Get-NetIPAddress"},
                                      {"address": "fe80::2%7", "prefix_length": 64,
                                       "source": "Get-NetIPAddress"}]}],
        "neighbors": [{"interface_index": 7, "address": "10.0.0.1",
                       "mac": "00:11:22:33:44:66", "state": "Stale"}],
    })


def request(db, path):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test-only") as client:
            return await client.get(path)
    return asyncio.run(run())


def test_snapshot_persistence_module_exists():
    assert find_spec("app.collectors.store") is not None


def test_full_snapshot_roundtrip_preserves_all_addresses_and_sources(tmp_path):
    from app.collectors.store import NetworkStore
    db = initialize_database(tmp_path / "snapshots.sqlite")
    store = NetworkStore(db)
    device = str(uuid4())
    run = store.collect(device, "test-only device", collector=snapshot)
    assert run["state"] == "completed"
    reopened = NetworkStore(Database(db.path, readonly=True))
    saved = reopened.latest(device)
    assert saved["id"] == run["id"]
    assert saved["deviceId"] == device
    assert saved["assetId"] is None
    assert saved["snapshot"] == snapshot().model_dump(mode="json")
    assert saved["snapshot"]["neighbors"][0]["online_verified"] is False
    assert reopened.devices()["items"][0]["id"] == device
    initialize_database(db.path)  # New tables must pass the project-owned DB guard.


def test_failed_collection_is_durable_and_not_replaced_by_previous_success(tmp_path):
    from app.collectors.store import NetworkStore
    store = NetworkStore(initialize_database(tmp_path / "snapshots.sqlite"))
    device = str(uuid4())
    first = store.collect(device, "test-only", collector=snapshot)

    def fail():
        raise RuntimeError("test-only failure with secret-like detail")

    result = store.collect(device, "test-only", collector=fail)
    assert result["state"] == "failed"
    assert result["errorCode"] == "windows_network_collection_failed"
    assert result["snapshot"] is None
    assert store.latest(device)["id"] == result["id"]
    page = store.history(device, limit=1)
    assert page["items"][0]["id"] == first["id"]
    assert page["nextCursor"] is not None
    assert store.history(device, cursor=page["nextCursor"])["items"][0]["id"] == result["id"]


def test_invalid_explicit_asset_mapping_is_rejected_without_creating_device(tmp_path):
    from app.collectors.store import NetworkStore
    store = NetworkStore(initialize_database(tmp_path / "snapshots.sqlite"))
    with pytest.raises(ValueError, match="asset"):
        store.collect(str(uuid4()), "test-only", asset_id=str(uuid4()), collector=snapshot)
    assert store.devices()["items"] == []


def test_snapshot_cannot_silently_change_explicit_asset_mapping(tmp_path):
    from app.collectors.store import NetworkStore
    store = NetworkStore(initialize_database(tmp_path / "snapshots.sqlite"))
    wrong = snapshot().model_copy(update={"asset_id": uuid4()})
    result = store.collect(str(uuid4()), "test-only", collector=lambda: wrong)
    assert result["state"] == "failed"
    assert result["snapshot"] is None


def test_readonly_store_never_starts_collection_or_creates_file(tmp_path):
    from app.collectors.store import NetworkStore
    path = tmp_path / "missing.sqlite"
    store = NetworkStore(Database(path, readonly=True))
    with pytest.raises(PermissionError):
        store.collect(str(uuid4()), "test-only", collector=snapshot)
    assert not path.exists()


def test_http_snapshot_routes_exist_and_get_is_readonly(tmp_path):
    db = initialize_database(tmp_path / "snapshots.sqlite")
    response = request(db, "/api/v1/network-devices")
    assert response.status_code == 200
    assert response.json() == {"items": [], "nextCursor": None}
    assert request(db, f"/api/v1/network-devices/{uuid4()}/snapshots/latest").status_code == 404
    assert request(db, "/api/v1/network-devices?limit=201").status_code == 422


def test_http_roundtrip_and_device_filter_do_not_mix_hosts(tmp_path):
    from app.collectors.store import NetworkStore
    db = initialize_database(tmp_path / "snapshots.sqlite")
    store = NetworkStore(db)
    first, second = str(uuid4()), str(uuid4())
    a = store.collect(first, "test-only A", collector=snapshot)
    store.collect(second, "test-only B", collector=snapshot)
    history = request(db, f"/api/v1/network-devices/{first}/snapshots").json()
    assert [row["id"] for row in history["items"]] == [a["id"]]
    assert request(db, f"/api/v1/network-devices/{first}/snapshots/latest").json() == a
    assert request(db, f"/api/v1/network-snapshots/{a['id']}").json() == a


def test_future_sample_is_recorded_as_failed_not_saved_as_a_current_observation(tmp_path):
    from app.collectors.store import NetworkStore
    store = NetworkStore(initialize_database(tmp_path / "snapshots.sqlite"))
    sample = snapshot().model_copy(update={"observed_at": "2099-01-01T00:00:00Z"})
    result = store.collect(str(uuid4()), "test-only", collector=lambda: sample)
    assert result["state"] == "failed"
    assert result["observedAt"] is None
    assert result["snapshot"] is None


def test_interrupted_collection_is_recovered_without_erasing_history(tmp_path):
    from sqlalchemy.orm import Session
    from app.collectors.models import NetworkRunRow
    from app.collectors.store import NetworkStore
    from app.discovery.types import utc_now
    db = initialize_database(tmp_path / "snapshots.sqlite")
    store = NetworkStore(db)
    device, old = str(uuid4()), str(uuid4())
    store.collect(device, "test-only", collector=snapshot)
    with Session(db.engine) as session, session.begin():
        session.add(NetworkRunRow(id=old, device_id=device, state="running", started_at=utc_now()))
    store.collect(device, "test-only", collector=snapshot)
    recovered = store.get(old)
    assert recovered["state"] == "interrupted"
    assert recovered["errorCode"] == "previous_collection_interrupted"
    assert len(store.history(device)["items"]) == 3


def test_explicit_existing_asset_is_preserved_and_never_inferred_from_addresses(tmp_path):
    from sqlalchemy.orm import Session
    from app.assets.models import AssetRow
    from app.collectors.store import NetworkStore
    from app.discovery.config import ScanSettings
    from app.discovery.types import utc_now
    db = initialize_database(tmp_path / "snapshots.sqlite")
    scope, _ = db.save_scope(ScanSettings(name="test-only", targets=["10.0.0.2"], ports=[80]))
    asset, device = str(uuid4()), str(uuid4())
    with Session(db.engine) as session, session.begin():
        session.add(AssetRow(id=asset, scope_id=scope, name="test-only", asset_kind="computer",
                            notes="", revision=1, created_at=utc_now(), updated_at=utc_now()))
    store = NetworkStore(db)
    result = store.collect(device, "test-only", asset_id=asset, collector=snapshot)
    assert result["assetId"] == asset
    assert result["associationSource"] == "operator_config"
    assert result["snapshot"]["asset_id"] == asset
    assert result["snapshot"]["identity_verified"] is False
    with pytest.raises(ValueError, match="mapping"):
        store.collect(device, "test-only", collector=snapshot)


def test_upgrade_from_previous_schema_backs_up_and_preserves_existing_jobs(tmp_path):
    from alembic import command
    from alembic.config import Config
    import sqlite3
    from app.discovery.config import ROOT, ScanSettings
    db = initialize_database(tmp_path / "snapshots.sqlite")
    scope, revision = db.save_scope(ScanSettings(name="test-only", targets=["10.0.0.2"], ports=[80]))
    job = db.begin_job(scope, revision, {})
    db.finish_job(job, "completed", {})
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with db.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.downgrade(config, "0003_automatic_discovery")
    initialize_database(db.path)
    assert db.get_job(job)["state"] == "completed"
    backups = list((tmp_path / "backups").glob("*.sqlite"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as old:
        assert old.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0003_automatic_discovery"
        assert old.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
