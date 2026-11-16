"""Repository bootstrap safety. Run with Python's standard-library unittest."""
import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workspace.py"
spec = importlib.util.spec_from_file_location("workspace", SCRIPT)
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)


class WorkspaceTests(unittest.TestCase):
    def test_paths_follow_checkout_not_current_working_directory(self):
        root = (Path(tempfile.gettempdir()) / "协作 空格目录" / "checkout").resolve()
        paths = workspace.layout(root)
        self.assertEqual(paths["database"], root / ".runtime/data/development.sqlite")
        self.assertEqual(paths["frontend_dist"], root / ".runtime/frontend/dist")
        self.assertNotEqual(paths["database"], root / "net-assistant/backend/data/inspection.sqlite")

    def test_configs_are_disabled_relative_and_never_overwrite_local_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace.write_configs(root)
            configs = root / ".runtime/configs"
            schedule = json.loads((configs / "daily-scan.local.json").read_text("utf-8"))
            self.assertFalse(schedule["enabled"])
            self.assertEqual(schedule["database"], "../data/development.sqlite")
            scope = json.loads((configs / "scope.local.json").read_text("utf-8"))
            self.assertEqual(scope["targets"], ["127.0.0.1"])
            self.assertFalse(scope["nmap_os_detection"])
            self.assertFalse(scope["mdns_enabled"])
            switches = json.loads((configs / "switches.local.json").read_text("utf-8"))
            self.assertFalse(switches["enabled"])
            self.assertEqual(switches["profiles"], [])
            terminal = configs / "terminal.local.json"
            terminal.write_text('{"targets": [], "preserved": true}', encoding="utf-8")
            workspace.write_configs(root)
            self.assertTrue(json.loads(terminal.read_text("utf-8"))["preserved"])

    def test_server_environment_cannot_inherit_live_project_plans(self):
        root = Path(tempfile.gettempdir()) / "isolated-checkout"
        env = workspace.server_environment(root, {
            "INSPECT_DB": "Z:/live.sqlite",
            "INSPECT_SCHEDULE_CONFIG": "Z:/live-plan.json",
            "inspect_terminal_config": "Z:/keys.json",
            "PATH": "retained", "NET_ASSISTANT_SWITCH_AUTH": "not-printed",
        })
        self.assertNotIn("INSPECT_DB", env)
        self.assertNotIn("INSPECT_SCHEDULE_CONFIG", env)
        self.assertNotIn("inspect_terminal_config", env)
        self.assertEqual(env["PATH"], "retained")

    def test_readiness_missing_database_does_not_create_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sqlite"
            with self.assertRaisesRegex(ValueError, "init"):
                workspace.check_database(path)
            self.assertFalse(path.exists())

    def test_readiness_rejects_early_0006_schema_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite"
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE alembic_version (version_num TEXT)")
                db.execute("INSERT INTO alembic_version VALUES ('0006_access_terminal')")
                db.execute("CREATE TABLE auth_users (id TEXT PRIMARY KEY)")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "schema"):
                workspace.check_database(path)
            self.assertEqual(path.read_bytes(), before)

    def test_readiness_accepts_not_null_primary_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.sqlite"
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE alembic_version (version_num TEXT)")
                db.execute("INSERT INTO alembic_version VALUES ('0006_access_terminal')")
                for table, column in workspace.PRIMARY_KEYS.items():
                    db.execute(f'CREATE TABLE "{table}" ("{column}" TEXT NOT NULL PRIMARY KEY)')
            workspace.check_database(path)

    def test_frontend_sync_excludes_generated_and_local_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "net-assistant/frontend"
            (source / "src").mkdir(parents=True)
            (source / "src/App.tsx").write_text("export default 1", encoding="utf-8")
            (source / ".env.local").write_text("SECRET=not-for-build", encoding="utf-8")
            (source / "node_modules").mkdir()
            (source / "node_modules/local-secret").write_text("private", encoding="utf-8")
            (source / "package.json").write_text("{}", encoding="utf-8")
            workspace.sync_frontend(root)
            target = root / ".runtime/frontend"
            self.assertTrue((target / "src/App.tsx").is_file())
            self.assertFalse((target / ".env.local").exists())
            self.assertFalse((target / "node_modules/local-secret").exists())

    def test_frontend_sync_removes_deleted_source_without_touching_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "net-assistant/frontend/src"
            source.mkdir(parents=True)
            (source / "kept.tsx").write_text("current", encoding="utf-8")
            workspace.sync_frontend(root)
            target = root / ".runtime/frontend"
            (target / "src/deleted.tsx").write_text("stale", encoding="utf-8")
            (target / "node_modules").mkdir()
            (target / "node_modules/keep").write_text("dependency", encoding="utf-8")
            workspace.sync_frontend(root)
            self.assertFalse((target / "src/deleted.tsx").exists())
            self.assertTrue((target / "node_modules/keep").is_file())


if __name__ == "__main__":
    unittest.main()
