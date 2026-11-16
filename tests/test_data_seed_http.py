"""Exercise the seed verifier with synthetic data over an actual loopback HTTP socket."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from test_data_seed import ROOT, make_source, seed

SCRIPT = ROOT / "scripts/verify_seed_http.py"
verifier = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location("verify_seed_http", SCRIPT)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)


class SeedHttpTests(unittest.TestCase):
    def test_seeded_history_login_pagination_relations_console_and_logout(self):
        self.assertIsNotNone(verifier, "Implement the real seeded HTTP verification.")
        with tempfile.TemporaryDirectory(prefix="seed-http-fixture-") as directory:
            root = Path(directory)
            make_source(root / "source.sqlite")
            bundle = root / "seed/inspection-seed.sqlite"
            seed.build_seed(root / "source.sqlite", bundle)
            report = verifier.verify(bundle)
            self.assertEqual(report["checked_counts"]["discovery_jobs"], 1)
            self.assertEqual(report["checked_counts"]["discovery_hosts"], 1)
            self.assertEqual(report["checked_counts"]["discovery_probes"], 1)
            self.assertEqual(report["checked_counts"]["asset_discovery_links"], 1)
            self.assertEqual(report["checked_counts"]["network_collection_runs"], 1)
            self.assertTrue(report["login_logout_verified"])
            self.assertTrue(report["business_rows_unchanged_after_http"])
            self.assertFalse(report["visual_browser_verification"])
            self.assertEqual(report["verification_account_location"], "temporary_database_only")


if __name__ == "__main__":
    unittest.main()
