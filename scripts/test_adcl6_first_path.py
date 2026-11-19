"""Filesystem controls for the joined journey's preparation helpers."""

import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from adcl6_first_path import (
    AUDIENCE,
    ORG,
    archive_running_tree,
    assert_approval_display,
    assert_approval_target,
    assert_outside_verdict,
    save,
)


class RunningTreeTests(unittest.TestCase):
    def test_archive_follows_the_checked_out_commit_and_refuses_dirty_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "cli/go/source.txt"
            source.parent.mkdir(parents=True)
            source.write_text("first")
            for path in (
                "awid/source.txt",
                "key-holder/source.txt",
                "naapp-lib/source.txt",
            ):
                file = root / path
                file.parent.mkdir()
                file.write_text(path)
            deployment = root / "deploy/team/render_env.py"
            deployment.parent.mkdir(parents=True)
            deployment.write_text("deployment renderer")

            def commit():
                subprocess.run(["git", "add", "."], cwd=root, check=True)
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=fixture@example.test",
                        "commit",
                        "-qm",
                        "fixture",
                    ],
                    cwd=root,
                    check=True,
                )
                return subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=root, text=True
                ).strip()

            first = commit()
            archive = Path(directory) / "source.tar"
            self.assertEqual(archive_running_tree(root, archive), first)
            with tarfile.open(archive) as contents:
                self.assertEqual(
                    contents.extractfile("cli/go/source.txt").read(), b"first"
                )
                self.assertIsNotNone(contents.getmember("awid/source.txt"))
                self.assertIsNotNone(contents.getmember("key-holder/source.txt"))
                self.assertIsNotNone(contents.getmember("naapp-lib/source.txt"))
                self.assertIsNotNone(contents.getmember("deploy/team/render_env.py"))
            source.write_text("second")
            with self.assertRaisesRegex(RuntimeError, "clean"):
                archive_running_tree(root, archive)
            second = commit()
            self.assertNotEqual(first, second)
            self.assertEqual(archive_running_tree(root, archive), second)
            with tarfile.open(archive) as contents:
                self.assertEqual(
                    contents.extractfile("cli/go/source.txt").read(), b"second"
                )


class SaveTests(unittest.TestCase):
    def test_new_json_is_private_even_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "inputs.json"
            previous_umask = os.umask(0)
            try:
                save(path, {"stage": "prepared"})
            finally:
                os.umask(previous_umask)
            self.assertEqual(json.loads(path.read_text()), {"stage": "prepared"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_replacing_public_json_publishes_a_private_complete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compose.json"
            path.write_text('{"old": true}')
            path.chmod(0o644)
            save(path, {"services": {"holder": {"user": "1003:1003"}}})
            self.assertEqual(
                json.loads(path.read_text()),
                {"services": {"holder": {"user": "1003:1003"}}},
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(path.with_suffix(".json.tmp").exists())


class ApprovalAssertionTests(unittest.TestCase):
    def test_display_accepts_expected_digest_and_refuses_another(self):
        text = f"human.add first second {ORG} {AUDIENCE}"
        assert_approval_display("a" * 64, text, "a" * 64, "first", "second")
        with self.assertRaisesRegex(AssertionError, "approval_digest_mismatch"):
            assert_approval_display("b" * 64, text, "a" * 64, "first", "second")

    def test_display_refuses_json_quotes_around_the_plain_digest(self):
        text = f"human.add first second {ORG} {AUDIENCE}"
        with self.assertRaisesRegex(AssertionError, "approval_digest_mismatch"):
            assert_approval_display(
                json.dumps("a" * 64), text, "a" * 64, "first", "second"
            )

    def test_request_accepts_expected_target_and_refuses_another(self):
        request = {"approver": "first", "act": {"target": {"person": "second"}}}
        assert_approval_target(request, "first", "second")
        request["act"]["target"]["person"] = "third"
        with self.assertRaisesRegex(AssertionError, "approval_target_mismatch"):
            assert_approval_target(request, "first", "second")

    def test_display_refuses_another_target_even_with_right_digest(self):
        text = f"human.add first third {ORG} {AUDIENCE}"
        with self.assertRaisesRegex(AssertionError, "approval_display_mismatch:second"):
            assert_approval_display("a" * 64, text, "a" * 64, "first", "second")


class OutsideAssertionTests(unittest.TestCase):
    def test_absent_and_later_evidence_do_not_become_creation(self):
        result = {
            "identity_valid": True,
            "id": "person",
            "human_id": "person",
            "kind": "human",
            "outcome": "nearest_human",
            "reason": "verified",
            "evidence": [
                {
                    "presence": "absent",
                    "issuer_authenticated_grade": None,
                    "proof": {"status": "not_evaluated"},
                }
            ],
        }
        assert_outside_verdict(result, "person", "none")
        with self.assertRaises(AssertionError):
            assert_outside_verdict(result, "person", "later")
        result["evidence"] = [
            {
                "presence": "present",
                "profile": "human_enrolled_later",
                "statement": {"status": "valid", "reason": "checked"},
                "proof": {"status": "valid", "reason": "checked"},
                "issuer_authenticated_grade": "passkey_uv",
                "proof_binds_grade": True,
                "currentness": "current",
                "continuity": "unknown",
                "can_approve_since": 1000,
            }
        ]
        assert_outside_verdict(result, "person", "later")
        with self.assertRaisesRegex(AssertionError, "outside_continuity_unknown"):
            assert_outside_verdict(result, "person", "creation")

    def test_low_grade_and_broken_continuity_cannot_pass_the_phase(self):
        evidence = {
            "statement": {"status": "valid", "reason": "checked"},
            "proof": {"status": "valid", "reason": "checked"},
            "issuer_authenticated_grade": "passkey_uv",
            "proof_binds_grade": True,
            "currentness": "current",
            "continuity": "unbroken",
        }
        result = {
            "identity_valid": True,
            "id": "person",
            "outcome": "nearest_human",
            "reason": "verified",
            "human_id": "person",
            "kind": "human",
            "evidence": [evidence],
        }
        assert_outside_verdict(result, "person")
        evidence["issuer_authenticated_grade"] = "password_only"
        with self.assertRaisesRegex(AssertionError, "outside_grade_below_passkey_uv"):
            assert_outside_verdict(result, "person")
        evidence["issuer_authenticated_grade"] = "passkey_uv"
        evidence["continuity"] = "broken"
        with self.assertRaisesRegex(AssertionError, "outside_continuity_broken"):
            assert_outside_verdict(result, "person")


if __name__ == "__main__":
    unittest.main()
