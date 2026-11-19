#!/usr/bin/env python3
"""Closed image-identity inputs; real image controls run in the packaged lab."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "naapp-lib/testing/src/aweb_naapp_testing/packaged_identity.py"
spec = importlib.util.spec_from_file_location("packaged_identity", PATH)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class PackagedIdentity(unittest.TestCase):
    def test_commit_matches_the_expected_full_source_sha(self):
        identity.require_commit("a" * 40, "a" * 40)
        for actual in (None, "", "b" * 40, "a" * 39):
            with (
                self.subTest(actual=actual),
                self.assertRaisesRegex(ValueError, "build identity"),
            ):
                identity.require_commit("a" * 40, actual)
        for expected in ("", "a" * 39, "A" * 40):
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(ValueError, "build identity"),
            ):
                identity.require_commit(expected, expected)

    def test_numeric_declared_and_observed_users_must_match_the_service(self):
        identity.require_user("10001:10001", [10001, 10001], (10001, 10001))
        for declared in (
            "",
            "secrets",
            "root",
            "0:0",
            "0:10001",
            "10001:0",
            "10001",
            "10002:10002",
        ):
            with (
                self.subTest(declared=declared),
                self.assertRaisesRegex(ValueError, "image USER"),
            ):
                identity.require_user(declared, [10001, 10001], (10001, 10001))
        for observed in (
            [0, 0],
            [10002, 10002],
            [10001, 0],
            [10001],
            ["10001", "10001"],
            [True, True],
        ):
            with (
                self.subTest(observed=observed),
                self.assertRaisesRegex(ValueError, "image USER"),
            ):
                identity.require_user("10001:10001", observed, (10001, 10001))


if __name__ == "__main__":
    unittest.main()
