"""Sensitivity controls for the real journey's admission-condition assertion."""

import json
from pathlib import Path
import re
import subprocess
import unittest


class InviteConditionAssertionTests(unittest.TestCase):
    def test_condition_is_explicit_and_matches_the_expected_human(self):
        source = Path(__file__).with_name("e2e-cross-registry-messaging.sh").read_text()
        match = re.search(r"(?ms)^assert_invite_human\(\) \{\n.*?^\}", source)
        self.assertIsNotNone(match, "the journey must check its admission conditions")
        for invite, expected, accepts in [
            ({"for_human": "person-a"}, "person-a", True),
            ({"for_human": "person-a"}, "person-b", False),
            ({"for_human": "person-a"}, "", False),
            ({"for_human": None}, "", True),
            ({"for_human": ""}, "", False),
            ({}, "", False),
        ]:
            with self.subTest(invite=invite, expected=expected):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        match[0] + '\nassert_invite_human "$1"',
                        "check",
                        expected,
                    ],
                    input=json.dumps(invite),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, accepts, result.stderr)


if __name__ == "__main__":
    unittest.main()
