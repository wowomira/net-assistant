"""Seed tests use invented data and temporary databases, never the working DB."""
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "net-assistant/backend"))
SCRIPT = ROOT / "scripts/data_seed.py"
seed = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location("data_seed", SCRIPT)
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)


def make_source(path):
    from app.discovery.config import ScanSettings
    from app.discovery.store import initialize_database
    from app.discovery.types import ProbeResult
    from app.assets.service import AssetRegistry
    from app.auth.store import AuthStore
    from app.collectors.contracts import NetworkSnapshot
    from app.collectors.store import NetworkStore
    db = initialize_database(path)
    settings = ScanSettings(name="seed-test-history", targets=["10.9.0.10"], ports=[80])
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot())
    db.record_discovery(job, "10.9.0.10", [ProbeResult("10.9.0.10", "icmp", "reply")], {
        "mac": "00:11:22:33:44:55", "discovery_methods": ["icmp:reply"],
        "confidence": "direct_response", "context": {},
    })
    db.finish_job(job, "partial", {"probeErrors": 1}, "budget_exceeded")
    with closing(sqlite3.connect(path)) as conn:
        host = conn.execute("SELECT id FROM discovery_hosts").fetchone()[0]
    asset = AssetRegistry(db).register(host, name="historical-test-device", reason="test fixture")
    device = "b48c69af-7144-410b-a125-e7c1bc415f1d"
    network = NetworkSnapshot.model_validate({
        "source": "windows_native", "observed_at": "2026-11-14T00:00:00Z",
        "interfaces": [], "neighbors": [],
    })
    NetworkStore(db).collect(device, "historical-local-device", collector=lambda: network)
    AuthStore(path).create_user("never-export-this-user", "not-exported-password-123!", "admin")
    db.engine.dispose()
    return job, host, asset["id"], device


class DataSeedTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(seed, "Implement scripts/data_seed.py before seeds can be built.")
        self.temp = tempfile.TemporaryDirectory(prefix="seed 中文 空格-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.sqlite"
        self.ids = make_source(self.source)
        self.output = self.root / "bundle/inspection-seed.sqlite"

    def build(self):
        return seed.build_seed(self.source, self.output)

    def test_build_preserves_business_rows_relations_and_never_writes_source(self):
        before = self.source.read_bytes()
        manifest = self.build()
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(manifest["tables"]["discovery_jobs"]["rows"], 1)
        self.assertEqual(manifest["tables"]["network_collection_runs"]["rows"], 1)
        with closing(sqlite3.connect(self.output)) as conn:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(conn.execute("SELECT id,state,error_code FROM discovery_jobs").fetchone(),
                             (self.ids[0], "partial", "budget_exceeded"))
            self.assertEqual(conn.execute("SELECT discovery_host_id,asset_id FROM asset_discovery_links").fetchone(),
                             (self.ids[1], self.ids[2]))
            self.assertEqual(conn.execute("SELECT count(*) FROM auth_users").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM terminal_sessions").fetchone()[0], 0)
            self.assertTrue(conn.execute("PRAGMA table_info(auth_users)").fetchall()[0][3])
        self.assertFalse(any("snapshot" in p.name for p in self.output.parent.iterdir()))
        seed.validate_seed(self.output)

    def test_nested_credentials_and_text_credentials_are_redacted_without_losing_evidence(self):
        secret = "fixture-only-secret-value"
        evidence = {"address": "10.9.0.10", "nested": [
            {"password": secret, "accessToken": secret, "community_string": secret,
             "identity_verified": False}],
            "url": f"https://user:{secret}@example.invalid/path?api_key={secret}",
            "header": f"Authorization: Bearer {secret}",
            "embedded": json.dumps({"clientSecret": secret, "status": "kept"}),
            "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n" + secret +
                   "\n-----END OPENSSH PRIVATE KEY-----"}
        with closing(sqlite3.connect(self.source)) as conn, conn:
            conn.execute("UPDATE discovery_probes SET evidence=?", (json.dumps(evidence),))
            conn.execute("CREATE TABLE unrelated_credentials (secret TEXT)")
            conn.execute("INSERT INTO unrelated_credentials VALUES (?)", (secret,))
        manifest = self.build()
        self.assertNotIn(secret.encode(), self.output.read_bytes())
        self.assertNotIn(secret, json.dumps(manifest))
        with closing(sqlite3.connect(self.output)) as conn:
            data = json.loads(conn.execute("SELECT evidence FROM discovery_probes").fetchone()[0])
            self.assertEqual(data["address"], "10.9.0.10")
            self.assertFalse(data["nested"][0]["identity_verified"])
            self.assertNotIn("password", data["nested"][0])
            self.assertFalse(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='unrelated_credentials'").fetchall())
        self.assertGreater(manifest["redactions"]["discovery_probes.evidence"], 0)

    def test_wal_commits_are_included_even_when_not_checkpointed(self):
        with closing(sqlite3.connect(self.source)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("UPDATE discovery_jobs SET error_code='committed-in-wal'")
            writer.commit()
            self.build()
        with closing(sqlite3.connect(self.output)) as conn:
            self.assertEqual(conn.execute("SELECT error_code FROM discovery_jobs").fetchone()[0],
                             "committed-in-wal")

    def test_captured_screenshots_are_copied_and_missing_files_are_reported(self):
        from app.discovery.types import ProbeResult
        from app.discovery.store import Database
        names = ["a" * 32 + ".png", "b" * 32 + ".png"]
        db = Database(self.source)
        db.record_probes(self.ids[0], [
            ProbeResult("10.9.0.10", "screenshot", "captured", evidence={"file": name})
            for name in names
        ])
        db.engine.dispose()
        screenshots = self.source.parent / "artifacts/screenshots"
        screenshots.mkdir(parents=True)
        (screenshots / names[0]).write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        manifest = self.build()
        self.assertEqual((self.output.parent / "artifacts/screenshots" / names[0]).read_bytes(),
                         b"\x89PNG\r\n\x1a\nfixture")
        self.assertEqual([entry["status"] for entry in manifest["screenshots"]],
                         ["copied", "missing"])
        target = self.root / "run/development.sqlite"
        seed.import_seed(self.output, target)
        self.assertTrue((target.parent / "artifacts/screenshots" / names[0]).is_file())

    def test_build_failure_leaves_no_published_bundle_and_does_not_replace_existing_seed(self):
        self.build()
        before = self.output.read_bytes()
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(self.output.read_bytes(), before)
        bad = self.root / "unrelated.sqlite"
        with closing(sqlite3.connect(bad)) as conn:
            conn.execute("CREATE TABLE unrelated (id TEXT)")
        other = self.root / "bad-bundle/inspection-seed.sqlite"
        with self.assertRaises(ValueError):
            seed.build_seed(bad, other)
        self.assertFalse(other.parent.exists())

    def test_existing_empty_database_requires_explicit_opt_in_and_imports_atomically(self):
        from app.discovery.store import initialize_database
        self.build()
        target = self.root / "run/development.sqlite"
        db = initialize_database(target)
        db.engine.dispose()
        before = target.read_bytes()
        with self.assertRaises(ValueError):
            seed.import_seed(self.output, target)
        self.assertEqual(target.read_bytes(), before)
        seed.import_seed(self.output, target, into_empty=True)
        with closing(sqlite3.connect(target)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM discovery_jobs").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM auth_users").fetchone()[0], 0)
        before = target.read_bytes()
        with self.assertRaises(ValueError):
            seed.import_seed(self.output, target, into_empty=True)
        self.assertEqual(target.read_bytes(), before)

    def test_account_only_database_is_not_overwritten_and_no_merge_is_attempted(self):
        from app.discovery.store import initialize_database
        from app.auth.store import AuthStore
        self.build()
        target = self.root / "run/development.sqlite"
        db = initialize_database(target)
        db.engine.dispose()
        AuthStore(target).create_user("keep-me", "keep-my-account-password-123!", "admin")
        before = target.read_bytes()
        with self.assertRaisesRegex(ValueError, "empty"):
            seed.import_seed(self.output, target, into_empty=True)
        self.assertEqual(target.read_bytes(), before)

    def test_tampered_seed_is_rejected_before_creating_runtime_database(self):
        self.build()
        with closing(sqlite3.connect(self.output)) as conn, conn:
            conn.execute("UPDATE discovery_jobs SET error_code='tampered'")
        target = self.root / "run/development.sqlite"
        with self.assertRaises(ValueError):
            seed.import_seed(self.output, target)
        self.assertFalse(target.exists())

    def test_empty_database_with_incompatible_schema_is_not_repaired_or_replaced(self):
        self.build()
        target = self.root / "bad-runtime.sqlite"
        with closing(sqlite3.connect(target)) as conn:
            conn.execute("CREATE TABLE unrelated(id TEXT)")
        before = target.read_bytes()
        with self.assertRaises(ValueError):
            seed.import_seed(self.output, target, into_empty=True)
        self.assertEqual(target.read_bytes(), before)

    def test_early_source_auth_schema_is_rebuilt_without_source_migration(self):
        with closing(sqlite3.connect(self.source)) as conn, conn:
            conn.execute("DROP TABLE auth_users")
            conn.execute("CREATE TABLE auth_users (id TEXT PRIMARY KEY)")
        before = self.source.read_bytes()
        self.build()
        self.assertEqual(self.source.read_bytes(), before)
        with closing(sqlite3.connect(self.output)) as conn:
            self.assertTrue(conn.execute("PRAGMA table_info(auth_users)").fetchall()[0][3])

    def test_failed_transaction_rolls_back_all_rows_and_can_be_retried(self):
        from app.discovery.store import initialize_database
        self.build()
        target = self.root / "run/development.sqlite"
        initialize_database(target).engine.dispose()
        real_digest = seed.table_digest

        def fail_on_runtime(connection, table):
            path = Path(connection.execute("PRAGMA database_list").fetchone()[2])
            if path == target:
                raise ValueError("injected runtime verification failure")
            return real_digest(connection, table)

        with patch.object(seed, "table_digest", side_effect=fail_on_runtime):
            with self.assertRaisesRegex(ValueError, "injected"):
                seed.import_seed(self.output, target, into_empty=True)
        with closing(sqlite3.connect(target)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM discovery_jobs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM network_devices").fetchone()[0], 0)
        self.assertFalse(target.with_suffix(".seed-import.json").exists())
        seed.import_seed(self.output, target, into_empty=True)

    def test_import_rechecks_empty_under_write_lock_after_concurrent_account_activity(self):
        from app.discovery.store import initialize_database
        self.build()
        target = self.root / "run/development.sqlite"
        initialize_database(target).engine.dispose()
        real_check = seed.assert_empty
        checks = 0

        def account_activity(connection, schema):
            nonlocal checks
            real_check(connection, schema)
            checks += 1
            if checks == 1:
                with closing(sqlite3.connect(target)) as writer, writer:
                    writer.execute("INSERT INTO auth_throttles(key,failures,window_start)"
                                   " VALUES ('concurrent-activity',1,0)")

        with patch.object(seed, "assert_empty", side_effect=account_activity):
            with self.assertRaisesRegex(ValueError, "empty"):
                seed.import_seed(self.output, target, into_empty=True)
        with closing(sqlite3.connect(target)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM discovery_jobs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM auth_throttles").fetchone()[0], 1)

    def test_workspace_init_uses_seed_once_and_never_resets_new_data(self):
        import workspace
        self.build()
        root = self.root / "checkout"
        paths = workspace.layout(root)
        self.assertIn("seed", paths, "workspace init needs to discover the private data seed")
        paths["seed"].parent.mkdir(parents=True)
        import shutil
        shutil.copy2(self.output, paths["seed"])
        shutil.copy2(seed.manifest_path(self.output), seed.manifest_path(paths["seed"]))
        with patch.object(workspace, "layout", return_value=paths):
            workspace.init_database()
            with closing(sqlite3.connect(paths["database"])) as conn, conn:
                conn.execute("UPDATE discovery_jobs SET error_code='new-local-data'")
            workspace.init_database()
        with closing(sqlite3.connect(paths["database"])) as conn:
            self.assertEqual(conn.execute("SELECT error_code FROM discovery_jobs").fetchone()[0],
                             "new-local-data")
            self.assertEqual(conn.execute("SELECT count(*) FROM auth_users").fetchone()[0], 0)
        configs = json.loads((root / ".runtime/configs/daily-scan.local.json").read_text("utf-8"))
        self.assertFalse(configs["enabled"])

    def test_simultaneous_import_is_refused_before_any_artifact_cleanup_can_race(self):
        self.build()
        target = self.root / "run/development.sqlite"
        target.parent.mkdir()
        self.assertTrue(hasattr(seed, "installation_lock"), "Serialize entire seed installations")
        with seed.installation_lock(target):
            with self.assertRaisesRegex(ValueError, "import"):
                seed.import_seed(self.output, target)
        self.assertFalse(target.exists())
        seed.import_seed(self.output, target)
        self.assertTrue(target.is_file())

    def test_screenshot_collision_rolls_back_only_files_owned_by_this_import(self):
        from app.discovery.store import Database
        from app.discovery.types import ProbeResult
        names = ["c" * 32 + ".png", "d" * 32 + ".png"]
        database = Database(self.source)
        database.record_probes(self.ids[0], [
            ProbeResult("10.9.0.10", "screenshot", "captured", evidence={"file": name})
            for name in names
        ])
        database.engine.dispose()
        original = self.source.parent / "artifacts/screenshots"
        original.mkdir(parents=True)
        for name in names:
            (original / name).write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        self.build()
        target = self.root / "run/development.sqlite"
        artifacts = target.parent / "artifacts/screenshots"
        artifacts.mkdir(parents=True)
        (artifacts / names[1]).write_bytes(b"existing-file-do-not-replace")
        with self.assertRaisesRegex(ValueError, "screenshot"):
            seed.import_seed(self.output, target)
        self.assertFalse(target.exists())
        self.assertFalse((artifacts / names[0]).exists())
        self.assertEqual((artifacts / names[1]).read_bytes(), b"existing-file-do-not-replace")

    def test_missing_runtime_with_orphan_wal_is_refused_without_deleting_sidecar(self):
        self.build()
        target = self.root / "run/development.sqlite"
        target.parent.mkdir()
        sidecar = Path(str(target) + "-wal")
        sidecar.write_bytes(b"orphan-journal-do-not-apply-to-a-new-db")
        with self.assertRaisesRegex(ValueError, "sidecar"):
            seed.import_seed(self.output, target)
        self.assertFalse(target.exists())
        self.assertEqual(sidecar.read_bytes(), b"orphan-journal-do-not-apply-to-a-new-db")


if __name__ == "__main__":
    unittest.main()
