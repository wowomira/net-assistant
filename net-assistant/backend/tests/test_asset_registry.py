"""Asset identity tests use invented observations, never edit the real experiment."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import httpx
import pytest
from alembic import command
from alembic.config import Config

from app.discovery.config import ROOT, ScanSettings
from app.discovery.store import Database, initialize_database
from app.discovery.types import ProbeResult
from app.main import create_app


def observation(db, address="10.9.0.10", mac="00:11:22:33:44:55",
                scope_name="lab", observed_at=None, confidence="direct_response",
                state="completed"):
    settings = ScanSettings(name=scope_name, targets=[address], ports=[80])
    scope, revision = db.save_scope(settings)
    # Historical migration fixtures must use the historical column set, not the
    # current ORM (which now also writes trigger/schedule_run_id).
    with sqlite3.connect(db.path) as connection:
        legacy = "trigger" not in {row[1] for row in connection.execute("PRAGMA table_info(discovery_jobs)")}
    if legacy:
        from uuid import uuid4
        from app.discovery.types import utc_now
        job = str(uuid4())
        with sqlite3.connect(db.path) as connection:
            connection.execute(
                "INSERT INTO discovery_jobs(id,scope_id,scope_revision,state,started_at,"
                "finished_at,config_snapshot,coverage,error_code) VALUES(?,?,?,?,?,?,?,?,?)",
                (job, scope, revision, state, utc_now(), None if state == "running" else utc_now(),
                 json.dumps(settings.snapshot()), "{}", None))
    else:
        job = db.begin_job(scope, revision, settings.snapshot())
    db.record_discovery(job, address, [ProbeResult(address, "icmp", "reply")], {
        "mac": mac, "discovery_methods": ["icmp:reply"], "confidence": confidence, "context": {},
    })
    if state != "running" and not legacy:
        db.finish_job(job, state, {})
    with sqlite3.connect(db.path) as connection:
        host = {"id": connection.execute(
            "SELECT id FROM discovery_hosts WHERE job_id=?", (job,)
        ).fetchone()[0]}
    if observed_at:
        # Only artificial data: explicit timestamps expose sorting by confirmation instead of observation.
        with db.engine.begin() as connection:
            from sqlalchemy import text
            connection.execute(text("UPDATE discovery_hosts SET observed_at=:time WHERE id=:id"),
                               {"time": observed_at, "id": host["id"]})
    return host["id"], job


@pytest.fixture
def registry(tmp_path):
    from app.assets.service import AssetRegistry
    return AssetRegistry(initialize_database(tmp_path / "assets.sqlite"))


def test_register_uses_stable_uuid_and_never_grants_collection(registry):
    from uuid import UUID
    host, job = observation(registry.db)
    asset = registry.register(host, name="lab-server", reason="Register a known lab target",
                              asset_kind="virtual_machine")
    assert str(UUID(asset["id"])) == asset["id"]
    assert asset["id"] != host
    assert asset["revision"] == 1
    assert asset["collection_access"] == "not_enrolled"
    assert asset["host_metrics"] is None
    assert asset["linked_observation_count"] == 1
    reopened = type(registry)(Database(registry.db.path, readonly=True))
    assert reopened.get_asset(asset["id"])["name"] == "lab-server"
    assert reopened.list_observations(asset["id"])["items"][0]["discovery_host_id"] == host
    with sqlite3.connect(registry.db.path) as connection:
        assert connection.execute(
            "SELECT management_status, collection_access FROM discovery_hosts WHERE id=?", (host,)
        ).fetchone() == ("discovered", "not_enrolled")
    assert registry.db.list_hosts(job)["items"][0]["asset_id"] == asset["id"]


def test_changed_ip_requires_confirmation_and_keeps_one_asset(registry):
    first, _ = observation(registry.db, observed_at="2026-11-14T10:00:00.000Z")
    second, _ = observation(registry.db, address="10.9.0.20",
                            observed_at="2026-11-15T10:00:00.000Z")
    asset = registry.register(first, name="one-device", reason="Initial registration")
    suggestion = registry.association(second)
    assert suggestion["asset_id"] is None
    assert suggestion["candidates"][0]["asset_id"] == asset["id"]
    assert suggestion["requires_confirmation"] is True
    assert registry.get_asset(asset["id"])["linked_observation_count"] == 1
    linked = registry.link(asset["id"], second, expected_revision=1, reason="Verified address change")
    assert linked["id"] == asset["id"]
    assert linked["revision"] == 2
    history = registry.list_observations(asset["id"])["items"]
    assert [item["address"] for item in history] == ["10.9.0.10", "10.9.0.20"]
    assert all("observed_at" in item and "job_id" in item for item in history)
    assert len(registry.list_assets()["items"]) == 1


def test_asset_and_observation_pages_batch_queries_and_keep_unlinked_assets(registry):
    from sqlalchemy import event

    first, _ = observation(registry.db, observed_at="2026-11-14T10:00:00.000Z")
    extra, _ = observation(registry.db, observed_at="2026-11-15T10:00:00.000Z")
    removed, _ = observation(registry.db)
    last, _ = observation(registry.db)
    linked = registry.register(first, name="linked", reason="Initial registration")
    registry.link(linked["id"], extra, expected_revision=1, reason="Confirm same device")
    unlinked = registry.register(removed, name="unlinked", reason="Initial registration")
    registry.unlink(unlinked["id"], removed, expected_revision=1, reason="Correct association")
    final = registry.register(last, name="last", reason="Initial registration")

    selects = []

    @event.listens_for(registry.db.engine, "before_cursor_execute")
    def record_select(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    page = registry.list_assets(limit=2)
    assert len(selects) == 1
    assert [(asset["id"], asset["linked_observation_count"], asset["last_observed_at"])
            for asset in page["items"]] == [
        (linked["id"], 2, "2026-11-15T10:00:00.000Z"), (unlinked["id"], 0, None)]
    assert registry.list_assets(limit=2, cursor=page["next_cursor"]) == {"items": [final], "next_cursor": None}

    selects.clear()
    observations = registry.list_observations(linked["id"])
    assert len(selects) == 2  # Asset existence check, then the full page including host and scope.
    assert [item["discovery_host_id"] for item in observations["items"]] == [first, extra]


def test_same_ip_different_device_is_not_merged_or_given_old_permissions(registry):
    first, _ = observation(registry.db)
    second, _ = observation(registry.db, mac="00:11:22:33:44:66")
    old = registry.register(first, name="old", reason="Register old device")
    suggestion = registry.association(second)
    assert suggestion["candidates"] == []
    assert suggestion["address_conflict"] is True
    assert suggestion["asset_id"] is None
    new = registry.register(second, name="replacement", reason="Confirmed different device at reused IP")
    assert new["id"] != old["id"]
    assert new["collection_access"] == "not_enrolled"
    assert len(registry.list_assets()["items"]) == 2


def test_duplicate_mac_is_ambiguous_not_an_auto_merge(registry):
    first, _ = observation(registry.db)
    second, _ = observation(registry.db, address="10.9.0.11")
    third, _ = observation(registry.db, address="10.9.0.12")
    a = registry.register(first, name="clone-A", reason="Known separate guest A")
    b = registry.register(second, name="clone-B", reason="Known separate guest B")
    result = registry.association(third)
    assert {candidate["asset_id"] for candidate in result["candidates"]} == {a["id"], b["id"]}
    assert result["ambiguous"] is True
    assert result["asset_id"] is None


def test_no_mac_or_name_cannot_invent_identity(registry):
    a, _ = observation(registry.db, mac=None)
    b, _ = observation(registry.db, address="10.9.0.11", mac=None)
    asset = registry.register(a, name="same-name", reason="Known target without MAC")
    assert registry.association(b)["candidates"] == []
    registry.link(asset["id"], b, expected_revision=1, reason="Independently verified identity")
    assert registry.get_asset(asset["id"])["linked_observation_count"] == 2


def test_multiple_interfaces_and_out_of_order_confirmation_keep_actual_observation_times(registry):
    newer, _ = observation(registry.db, observed_at="2026-11-15T10:00:00.000Z")
    older, _ = observation(registry.db, address="10.9.0.11", mac="00:11:22:33:44:66",
                           observed_at="2026-11-14T10:00:00.000Z")
    asset = registry.register(newer, name="multi-interface", reason="First record")
    registry.link(asset["id"], older, expected_revision=1, reason="Verified second interface")
    current = registry.get_asset(asset["id"])
    assert current["last_observed_at"] == "2026-11-15T10:00:00.000Z"
    assert "current_ip" not in current
    assert {h["mac"] for h in registry.list_observations(asset["id"])["items"]} == {
        "00:11:22:33:44:55", "00:11:22:33:44:66"}


def test_cross_scope_candidates_and_manual_link_are_blocked(registry):
    from app.assets.service import RegistryError
    a, _ = observation(registry.db)
    b, _ = observation(registry.db, scope_name="other-network")
    asset = registry.register(a, name="A", reason="Network A")
    assert registry.association(b)["candidates"] == []
    with pytest.raises(RegistryError) as error:
        registry.link(asset["id"], b, expected_revision=1, reason="Try cross scope")
    assert error.value.code == "scope_mismatch"
    assert registry.get_asset(asset["id"])["revision"] == 1


def test_link_is_idempotent_but_reassignment_requires_audited_unlink(registry):
    from app.assets.service import RegistryError
    a, _ = observation(registry.db)
    b, _ = observation(registry.db, address="10.9.0.11")
    asset = registry.register(a, name="A", reason="Register A")
    other = registry.register(b, name="B", reason="Register B")
    again = registry.link(asset["id"], a, expected_revision=1, reason="Retry")
    assert again["revision"] == 1
    assert len(registry.list_audit(asset["id"])["items"]) == 1
    with pytest.raises(RegistryError) as error:
        registry.link(other["id"], a, expected_revision=1, reason="Wrong reassignment")
    assert error.value.code == "observation_already_linked"
    registry.unlink(asset["id"], a, expected_revision=1, reason="Correct original misidentification")
    assert registry.association(a)["asset_id"] is None
    assert registry.list_observations(asset["id"])["items"] == []
    registry.link(other["id"], a, expected_revision=1, reason="Confirmed correct asset B")
    assert registry.association(a)["asset_id"] == other["id"]
    assert [e["action"] for e in registry.list_audit(asset["id"])["items"]] == ["registered", "unlinked"]
    assert registry.db.list_probes(registry.db.list_jobs()["items"][0]["id"])["items"]


def test_stale_revision_and_failed_write_leave_no_partial_link_or_audit(registry):
    from app.assets.service import RegistryError
    a, _ = observation(registry.db)
    b, _ = observation(registry.db, address="10.9.0.11")
    asset = registry.register(a, name="before", reason="Initial")
    registry.update(asset["id"], expected_revision=1, reason="Rename",
                    name="after", owner="team", notes="管理备注")
    with pytest.raises(RegistryError) as error:
        registry.link(asset["id"], b, expected_revision=1, reason="Stale client")
    assert error.value.code == "revision_conflict"
    assert registry.association(b)["asset_id"] is None
    assert registry.get_asset(asset["id"])["revision"] == 2
    assert len(registry.list_audit(asset["id"])["items"]) == 2
    with sqlite3.connect(registry.db.path) as connection:
        connection.execute("CREATE TRIGGER fail_asset_audit BEFORE INSERT ON asset_audit_events "
                           "BEGIN SELECT RAISE(ABORT, 'test audit write failure'); END")
    with pytest.raises(Exception, match="audit write failure"):
        registry.link(asset["id"], b, expected_revision=2, reason="Must roll back atomically")
    assert registry.association(b)["asset_id"] is None
    assert registry.get_asset(asset["id"])["revision"] == 2


@pytest.mark.parametrize("confidence,state", [
    ("candidate_only", "completed"), ("direct_response", "running"),
    ("direct_response", "failed"), ("direct_response", "interrupted"),
])
def test_unfinished_or_candidate_observations_cannot_be_confirmed(registry, confidence, state):
    from app.assets.service import RegistryError
    host, _ = observation(registry.db, confidence=confidence, state=state)
    with pytest.raises(RegistryError) as error:
        registry.register(host, name="not-confirmed", reason="Should not be accepted")
    assert error.value.code == "observation_not_confirmable"
    assert registry.list_assets()["items"] == []


@pytest.mark.parametrize("mac", ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "bad"])
def test_invalid_mac_cannot_produce_match_candidates(registry, mac):
    a, _ = observation(registry.db, mac=mac)
    b, _ = observation(registry.db, address="10.9.0.11", mac=mac)
    registry.register(a, name="a", reason="Known target")
    assert registry.association(b)["candidates"] == []


def test_metadata_validation_missing_assets_and_readonly_prevent_writes(registry):
    from app.assets.service import RegistryError
    from pydantic import ValidationError
    a, _ = observation(registry.db)
    with pytest.raises(ValidationError):
        registry.register(a, name=" ", reason="why")
    with pytest.raises(ValidationError):
        registry.register(a, name="a", reason=" ")
    with pytest.raises(RegistryError) as error:
        registry.get_asset("missing")
    assert error.value.code == "asset_not_found"
    readonly = type(registry)(Database(registry.db.path, readonly=True))
    with pytest.raises(PermissionError):
        readonly.register(a, name="x", reason="not allowed")
    assert registry.list_assets()["items"] == []


def test_pagination_does_not_drop_observations_and_audit(registry):
    a, _ = observation(registry.db)
    b, _ = observation(registry.db, address="10.9.0.11")
    asset = registry.register(a, name="a", reason="first")
    registry.link(asset["id"], b, expected_revision=1, reason="second")
    for method in (registry.list_observations, registry.list_audit):
        first = method(asset["id"], limit=1)
        second = method(asset["id"], limit=1, cursor=first["next_cursor"])
        assert len(first["items"]) == len(second["items"]) == 1
        assert first["items"][0]["id"] != second["items"][0]["id"]
        assert second["next_cursor"] is None


def test_upgrade_old_database_preserves_evidence_and_restorable_backup(tmp_path):
    path = tmp_path / "old.sqlite"
    db = Database(path)
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with db.engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_discovery")
    observation(db)
    with sqlite3.connect(path) as connection:
        before = connection.execute("SELECT * FROM discovery_probes").fetchall()
    initialize_database(path)
    backups = list((tmp_path / "backups").glob("*.sqlite"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert restored.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0001_discovery"
        assert restored.execute("SELECT * FROM discovery_probes").fetchall() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0006_access_terminal"
        assert connection.execute("SELECT * FROM discovery_probes").fetchall() == before
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    initialize_database(path)
    assert len(list((tmp_path / "backups").glob("*.sqlite"))) == 1


@pytest.mark.anyio
async def test_asset_read_api_contract_and_no_http_writes(registry):
    host, job = observation(registry.db)
    asset = registry.register(host, name="api", reason="API fixture")
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=registry.db.path))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/assets")
        assert response.status_code == 200
        body = response.json()["items"][0]
        assert body["id"] == asset["id"]
        assert body["collectionAccess"] == "not_enrolled"
        assert body["hostMetrics"] is None
        assert body["linkedObservationCount"] == 1
        assert response.headers["Cache-Control"] == "no-store"
        detail = await client.get(f"/api/v1/assets/{asset['id']}")
        assert detail.json()["name"] == "api"
        history = await client.get(f"/api/v1/assets/{asset['id']}/observations")
        assert history.json()["items"][0]["discoveryHostId"] == host
        assert "observedAt" in history.json()["items"][0]
        audit = await client.get(f"/api/v1/assets/{asset['id']}/audit")
        assert audit.json()["items"][0]["actor"] == "local_cli"
        association = await client.get(f"/api/v1/discovery-hosts/{host}/asset-association")
        assert association.json()["assetId"] == asset["id"]
        old_hosts = await client.get(f"/api/v1/discovery-jobs/{job}/hosts")
        assert old_hosts.json()["items"][0]["assetId"] == asset["id"]
        assert old_hosts.json()["items"][0]["managementStatus"] == "discovered"
        assert (await client.post("/api/v1/assets", json={})).status_code == 401
        assert (await client.patch(f"/api/v1/assets/{asset['id']}", json={})).status_code == 401
        bad = await client.get("/api/v1/assets?limit=201")
        assert bad.status_code == 422
        missing = await client.get("/api/v1/assets/missing")
        assert missing.status_code == 404
        assert missing.json()["code"] == "asset_not_found"
        assert missing.json()["requestId"]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_local_cli_executes_without_scanning_and_conflicts_are_structured(tmp_path):
    path = tmp_path / "cli.sqlite"
    db = initialize_database(path)
    host, _ = observation(db)

    def call(*arguments):
        return subprocess.run([sys.executable, "-m", "app.assets.cli", "--database", str(path),
                               *arguments], capture_output=True, text=True, encoding="utf-8",
                              cwd=ROOT, timeout=15)

    result = call("register", "--host-id", host, "--name", "命令行测试资产", "--reason", "fixture")
    assert result.returncode == 0, result.stderr
    asset = json.loads(result.stdout)
    assert asset["name"] == "命令行测试资产"
    duplicate = call("register", "--host-id", host, "--name", "duplicate", "--reason", "retry")
    assert duplicate.returncode == 2
    assert json.loads(duplicate.stderr)["code"] == "observation_already_linked"
    assert db.list_jobs()["items"][0]["state"] == "completed"
    assert len(db.list_jobs()["items"]) == 1


def old_database(path):
    db = Database(path)
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with db.engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_discovery")
    return db


def test_failed_migration_rolls_back_new_schema_and_keeps_old_version(tmp_path, monkeypatch):
    import app.discovery.store as store
    path = tmp_path / "atomic.sqlite"
    db = old_database(path)
    observation(db)
    real_upgrade = command.upgrade

    def fail_after_ddl(*args, **kwargs):
        real_upgrade(*args, **kwargs)
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(store.command, "upgrade", fail_after_ddl)
    with pytest.raises(RuntimeError, match="injected migration"):
        initialize_database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0001_discovery"
        assert connection.execute("SELECT count(*) FROM discovery_probes").fetchone()[0] == 1
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='assets'").fetchall() == []
    assert len(list((tmp_path / "backups").glob("*.sqlite"))) == 1


def test_backup_failure_aborts_before_migration(tmp_path, monkeypatch):
    import app.discovery.store as store
    path = tmp_path / "backup-failure.sqlite"
    old_database(path)

    def fail_backup(_):
        raise OSError("backup destination unavailable")

    monkeypatch.setattr(store, "backup_database", fail_backup)
    with pytest.raises(OSError, match="backup destination"):
        initialize_database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0001_discovery"
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name='assets'").fetchall()


def test_concurrent_writers_cannot_both_accept_the_same_revision(registry):
    from concurrent.futures import ThreadPoolExecutor
    from app.assets.service import RegistryError
    a, _ = observation(registry.db)
    b, _ = observation(registry.db, address="10.9.0.11")
    c, _ = observation(registry.db, address="10.9.0.12")
    asset = registry.register(a, name="concurrent", reason="Initial")

    def link(host):
        try:
            registry.link(asset["id"], host, expected_revision=1, reason="Concurrent confirmation")
            return "linked"
        except RegistryError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(link, [b, c]))
    assert sorted(results) == ["linked", "revision_conflict"]
    assert registry.get_asset(asset["id"])["linked_observation_count"] == 2
    assert registry.get_asset(asset["id"])["revision"] == 2
    assert len(registry.list_audit(asset["id"])["items"]) == 2


def test_suggestion_normalizes_mac_and_does_not_reuse_withdrawn_evidence(registry):
    a, _ = observation(registry.db, mac="00-11-22-33-44-AA")
    b, _ = observation(registry.db, address="10.9.0.11", mac="00:11:22:33:44:aa")
    asset = registry.register(a, name="a", reason="Initial")
    assert registry.association(b)["candidates"][0]["asset_id"] == asset["id"]
    registry.unlink(asset["id"], a, expected_revision=1, reason="Wrong identity")
    assert registry.association(b)["candidates"] == []
    assert len(registry.list_audit(asset["id"])["items"]) == 2


def test_candidate_limit_signals_truncation_and_does_not_autolink(registry):
    for i in range(21):
        host, _ = observation(registry.db, address=f"10.9.0.{i+1}")
        registry.register(host, name=f"duplicate-mac-{i}", reason="Separate artificial test target")
    another, _ = observation(registry.db, address="10.9.0.50")
    result = registry.association(another)
    assert len(result["candidates"]) == 20
    assert result["candidates_truncated"] is True
    assert result["ambiguous"] is True
    assert result["asset_id"] is None


def test_registration_rolls_back_if_audit_cannot_be_written(registry):
    host, _ = observation(registry.db)
    with sqlite3.connect(registry.db.path) as connection:
        connection.execute("CREATE TRIGGER fail_registration BEFORE INSERT ON asset_audit_events "
                           "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
    with pytest.raises(Exception, match="audit unavailable"):
        registry.register(host, name="not-created", reason="Must save atomically")
    assert registry.list_assets()["items"] == []
    assert registry.association(host)["asset_id"] is None


def test_cli_obeys_existing_scan_writer_lock(registry):
    from app.discovery.store import scan_writer_lock
    host, _ = observation(registry.db)
    with scan_writer_lock(registry.db.path):
        result = subprocess.run([
            sys.executable, "-m", "app.assets.cli", "--database", str(registry.db.path),
            "register", "--host-id", host, "--name", "locked", "--reason", "Should refuse"],
            capture_output=True, text=True, encoding="utf-8", timeout=15, cwd=ROOT)
    assert result.returncode == 2
    assert json.loads(result.stderr)["code"] == "storage_or_writer_busy"
    assert registry.list_assets()["items"] == []


@pytest.mark.anyio
async def test_asset_api_missing_database_is_503_and_does_not_create_file(tmp_path):
    path = tmp_path / "missing.sqlite"
    transport = httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=path))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/assets")
        assert response.status_code == 503
        assert response.json()["code"] == "database_unavailable"
        assert not path.exists()


@pytest.mark.anyio
async def test_openapi_asset_paths_are_readonly_and_models_expose_nullable_identity(registry):
    schema = create_app(allow_anonymous_reads=True, database_path=registry.db.path).openapi()
    for path, operations in schema["paths"].items():
        if path.startswith("/api/v1/assets") or path.endswith("/asset-association"):
            assert set(operations) == {"get"}
    asset_schema = schema["components"]["schemas"]["AssetView"]["properties"]
    assert asset_schema["id"]["type"] == "string"
    assert asset_schema["hostMetrics"]["type"] == "null"
    assert asset_schema["collectionAccess"]["const"] == "not_enrolled"
    host_schema = schema["components"]["schemas"]["HostView"]["properties"]
    assert {"type": "null"} in host_schema["assetId"]["anyOf"]


def test_migrated_schema_matches_persistence_models(registry):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from app.discovery.models import Base
    with registry.db.engine.connect() as connection:
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert differences == []


def test_local_cli_metadata_edit_requires_revision_and_cannot_set_collection_access(registry):
    host, _ = observation(registry.db)
    asset = registry.register(host, name="before", reason="Initial")
    updated = subprocess.run([
        sys.executable, "-m", "app.assets.cli", "--database", str(registry.db.path),
        "update", "--asset-id", asset["id"], "--expected-revision", "1", "--reason", "Renaming",
        "--name", "after", "--owner", "team"], capture_output=True, text=True, encoding="utf-8",
        timeout=15, cwd=ROOT)
    assert updated.returncode == 0, updated.stderr
    result = json.loads(updated.stdout)
    assert result["name"] == "after"
    assert result["revision"] == 2
    assert result["owner"] == "team"
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        registry.update(asset["id"], expected_revision=2, reason="Not an authorization entry",
                        collection_access="granted")
    assert registry.get_asset(asset["id"])["collection_access"] == "not_enrolled"
    assert registry.get_asset(asset["id"])["revision"] == 2


def test_real_http_smoke_reads_registry_from_isolated_database(registry):
    import os
    from app.auth.store import AuthStore
    access = AuthStore(registry.db.path)
    access.create_user("smoke-test", "isolated-smoke-password-751!", "viewer")
    token = access.login("smoke-test", "isolated-smoke-password-751!", "127.0.0.1")["token"]
    host, _ = observation(registry.db)
    asset = registry.register(host, name="real-http", reason="HTTP fixture")
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/smoke_test.py"), "--asset-id", asset["id"]],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=25,
        env={**os.environ, "INSPECT_DB": str(registry.db.path), "PYTHONIOENCODING": "utf-8",
             "INSPECT_SMOKE_SESSION": token})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: real HTTP asset registry" in result.stdout
    assert registry.get_asset(asset["id"])["revision"] == 1


def test_verifier_restores_backup_only_to_temporary_file_and_does_not_mutate_live_db(tmp_path):
    from app.assets.service import AssetRegistry
    path = tmp_path / "verify.sqlite"
    old = old_database(path)
    host, _ = observation(old)
    registry = AssetRegistry(initialize_database(path))
    asset = registry.register(host, name="verify", reason="Fixture")
    backups = list((tmp_path / "backups").glob("*.sqlite"))
    output = tmp_path / "verification.json"
    result = subprocess.run([
        sys.executable, "-m", "scripts.verify_asset_registry",
        "--database", str(path), "--backup", str(backups[0]), "--output", str(output)],
        capture_output=True, text=True, encoding="utf-8", timeout=20, cwd=ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["backupRestoreVerified"] is True
    assert report["backupSchemaVersion"] == "0001_discovery"
    assert report["registryRowCounts"] == {
        "assets": 1, "asset_discovery_links": 1, "asset_audit_events": 1}
    assert report["assets"][0]["id"] == asset["id"]
    assert registry.get_asset(asset["id"])["revision"] == 1
    assert len(list((tmp_path / "backups").glob("*.sqlite"))) == 1


def test_verifier_refuses_to_use_database_as_output(registry):
    before = registry.db.path.read_bytes()
    result = subprocess.run([
        sys.executable, "-m", "scripts.verify_asset_registry",
        "--database", str(registry.db.path), "--output", str(registry.db.path)],
        capture_output=True, text=True, encoding="utf-8", timeout=20, cwd=ROOT)
    assert result.returncode != 0
    assert registry.db.path.read_bytes() == before
