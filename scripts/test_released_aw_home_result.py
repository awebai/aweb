import unittest

from released_aw_home_result import require_upgrade_results

WRITER = """    registry_upgrade_test.go:222: released aw wrote the home
--- PASS: TestRegistryUpgradeFrom13658 (0.54s)
    --- PASS: TestRegistryUpgradeFrom13658/implicit_local_init (0.50s)
"""
READER_RESULTS = {
    name: f"        --- PASS: TestRegistryUpgradeFrom13658/implicit_local_init/{name} (0.01s)\n"
    for name in ("later_command", "wake_identity", "wake_after_team_state_rewrite")
}


class ReleasedHomeResultTests(unittest.TestCase):
    def test_complete_result(self):
        require_upgrade_results(WRITER + "".join(READER_RESULTS.values()))

    def test_passing_writer_and_parent_do_not_cover_missing_reader(self):
        for missing in READER_RESULTS:
            with self.subTest(missing=missing):
                present = "".join(
                    line for name, line in READER_RESULTS.items() if name != missing
                )
                with self.assertRaisesRegex(
                    ValueError, f"Released-home reader did not pass: {missing}$"
                ):
                    require_upgrade_results(WRITER + present)
