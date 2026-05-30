import unittest
from pathlib import Path

from replay_piv_auto_apdu_fixtures import replay_file


REPO_ROOT = Path(__file__).resolve().parents[2]


class PivAutoFixtureReplayTests(unittest.TestCase):
    def test_nist_sd33_fixtures_replay(self):
        fixture_dir = REPO_ROOT / "test-vectors" / "nist-sd33-apdu"
        files = sorted(fixture_dir.glob("nist_special_database_33_card_*.json"))
        self.assertGreaterEqual(len(files), 5)
        total = 0
        for path in files:
            report = replay_file(path)
            self.assertEqual(report["errors"], [], path)
            self.assertGreater(report["general_authenticate_count"], 0, path)
            total += report["general_authenticate_count"]
        self.assertGreaterEqual(total, 20)


if __name__ == "__main__":
    unittest.main()
