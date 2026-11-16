"""Current source completeness, Git line-endings and private-content release gates."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collaboration_snapshot as snapshot


class DeliverySourceTests(unittest.TestCase):
    def test_snapshot_keeps_untracked_code_and_redacts_only_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root, target = Path(directory) / "source", Path(directory) / "candidate"
            (root / "app").mkdir(parents=True)
            (root / "docs").mkdir()
            (root / "frontend/src/data").mkdir(parents=True)
            code = b'address = "10.9.0.10"\r\n'
            (root / "app/untracked.py").write_bytes(code)
            (root / "frontend/src/data/model.ts").write_bytes(b"export const model = 1;\n")
            (root / "docs/history.md").write_bytes(
                b"10.9.0.10 AA:BB:CC:DD:EE:FF DESKTOP-EXAMPLE\r\nsecond line\r\n")
            names = b"app/untracked.py\0docs/history.md\0frontend/src/data/model.ts\0already-deleted.py\0"
            with patch.object(snapshot.subprocess, "check_output", return_value=names):
                manifest = snapshot.build(target, root)
            self.assertTrue(manifest["all_program_code_copied_byte_for_byte"])
            self.assertEqual((target / "app/untracked.py").read_bytes(), code)
            self.assertTrue((target / "frontend/src/data/model.ts").is_file())
            history = (target / "docs/history.md").read_text("utf-8")
            self.assertNotIn(b"\r\r\n", (target / "docs/history.md").read_bytes())
            self.assertNotIn("10.9.0.10", history)
            self.assertNotIn("AA:BB:CC:DD:EE:FF", history)
            snapshot.verify(target)
            # Git's expected CRLF conversion must not produce a false corruption.
            (target / "app/untracked.py").write_bytes(code.replace(b"\r\n", b"\n"))
            snapshot.verify(target)
            (target / "app/untracked.py").write_bytes(b"code was actually lost\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                snapshot.verify(target)

    def test_tracked_private_database_or_real_token_blocks_release_before_copy(self):
        for name, content in [
            ("inspection.sqlite", b"database"),
            ("scope.local.json", b"{}"),
            ("credentials.txt", ("ghp_" + "a" * 36).encode()),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root, target = Path(directory) / "source", Path(directory) / "candidate"
                root.mkdir()
                (root / name).write_bytes(content)
                with patch.object(snapshot.subprocess, "check_output",
                                  return_value=name.encode() + b"\0"):
                    with self.assertRaises(ValueError):
                        snapshot.build(target, root)
                self.assertFalse(target.exists())

    def test_source_snapshot_never_overwrites_an_existing_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "new"):
                snapshot.build(Path(directory), Path(directory))


if __name__ == "__main__":
    unittest.main()
