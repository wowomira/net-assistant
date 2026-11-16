"""Portable delivery gates; standard-library tests run before dependencies exist."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


class PortableRuntimeTests(unittest.TestCase):
    def support(self):
        import runtime_support
        return runtime_support

    def test_archive_rejects_traversal_drive_and_symlinks_without_writes(self):
        support = self.support()
        for name in ("../escape", "C:/escape", "/escape", "ok/../../escape", "ok\\..\\escape"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "bad.zip"
                with zipfile.ZipFile(archive, "w") as z:
                    z.writestr("legitimate", "do not partially extract")
                    z.writestr(name, "bad")
                target = Path(directory) / "out"
                with self.assertRaises(ValueError):
                    support.extract_zip(archive, target)
                self.assertFalse(target.exists())
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "link.zip"
            with zipfile.ZipFile(archive, "w") as z:
                entry = zipfile.ZipInfo("link")
                entry.external_attr = 0o120777 << 16
                z.writestr(entry, "outside")
            with self.assertRaises(ValueError):
                support.extract_zip(archive, Path(directory) / "out")

    def test_checksum_mismatch_and_missing_required_file_refuse_install(self):
        support = self.support()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resource"
            path.write_bytes(b"partial download")
            with self.assertRaisesRegex(ValueError, "checksum"):
                support.check_hash(path, "0" * 64)
            with self.assertRaises((ValueError, FileNotFoundError)):
                support.check_hash(path.with_name("missing"), "0" * 64)

    def test_resource_manifest_must_match_every_file_not_just_count(self):
        support = self.support()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.whl").write_bytes(b"wheel")
            manifest = {"files": {"a.whl": support.sha256(root / "a.whl")}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            support.verify_resources(root)
            (root / "a.whl").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                support.verify_resources(root)

    def test_portable_environment_uses_checkout_tools_and_scrubs_borrowed_locations(self):
        support = self.support()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "朋友 空格"
            environment = support.runtime_environment(root, {
                "PATH": "E:/author-tools", "PLAYWRIGHT_BROWSERS_PATH": "C:/private-browser",
                "INSPECT_DB": "C:/private.sqlite", "NET_ASSISTANT_GATUS": "E:/gatus.exe",
                "SystemRoot": "C:/Windows",
            })
            self.assertNotIn("E:/author-tools", environment["PATH"])
            self.assertNotIn("INSPECT_DB", environment)
            self.assertEqual(environment["NET_ASSISTANT_GATUS"],
                             str(root.resolve() / ".runtime/tools/gatus/gatus.exe"))
            self.assertEqual(environment["PLAYWRIGHT_BROWSERS_PATH"],
                             str(root.resolve() / ".runtime/tools/browsers"))

    def test_embedded_runtime_gets_relative_project_paths_not_author_paths(self):
        support = self.support()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / ".runtime/python"
            python.mkdir(parents=True)
            (python / "python313._pth").write_text("python313.zip\n.\n#import site\n", encoding="utf-8")
            support.configure_embedded_python(root)
            content = (python / "python313._pth").read_text("utf-8")
            self.assertIn("Lib/site-packages", content)
            self.assertIn("../../scripts", content)
            self.assertIn("../../net-assistant/backend", content)
            self.assertNotIn(str(root), content)

    def test_nmap_import_requires_databases_and_copies_into_project(self):
        import runtime_manager
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            source = Path(directory) / "external Nmap"
            source.mkdir()
            (source / "nmap.exe").write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                runtime_manager.import_nmap(source, root)
            self.assertFalse((root / ".runtime/tools/nmap").exists())
            for name in runtime_manager.NMAP_REQUIRED:
                if not (source / name).exists():
                    (source / name).write_text("fixture", encoding="utf-8")
            (source / "private.key").write_text("never copy", encoding="utf-8")
            runtime_manager.import_nmap(source, root)
            self.assertTrue((root / ".runtime/tools/nmap/nmap-services").is_file())
            self.assertFalse((root / ".runtime/tools/nmap/private.key").exists())
            with self.assertRaisesRegex(ValueError, "exists"):
                runtime_manager.import_nmap(source, root)

    def test_worker_selection_is_explicit_and_defaults_to_none(self):
        import runtime_manager
        with tempfile.TemporaryDirectory() as directory:
            configs = Path(directory)
            self.assertEqual(runtime_manager.worker_selection(configs), [])
            (configs / "collection.local.json").write_text('{"enabled":false}', encoding="utf-8")
            self.assertEqual(runtime_manager.worker_selection(configs), [])
            (configs / "switches.local.json").write_text('{"enabled":true}', encoding="utf-8")
            self.assertEqual(runtime_manager.worker_selection(configs), ["switches"])


if __name__ == "__main__":
    unittest.main()
