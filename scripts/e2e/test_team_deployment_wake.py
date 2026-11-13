#!/usr/bin/env python3
"""The full-event wake helper's checks, without a container.

fixtures/team_deployment_wake/verified.txt and unverified.txt are the output of
channel-core's own formatAwakeningForAgent (channel-core/src/channel.ts) for a
mail from a local seat, built from source at main 184c7e02d: the exact text the
broker submits to a session. The transcript lines follow the keys of real Claude
Code transcript entries. The in-container transcript reader is the same Node
script the helper sends; these tests run it with the local node.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import team_deployment_wake as wake  # noqa: E402

FIXTURES = HERE / "fixtures" / "team_deployment_wake"
VERIFIED = (FIXTURES / "verified.txt").read_text()
UNVERIFIED = (FIXTURES / "unverified.txt").read_text()
MESSAGE_ID = "0192b7e4-1c2d-7a3b-9e4f-5a6b7c8d9e0f"
# Claude names a session's transcript by its UUID.
PARENT = "5b1f0c2e-8d4a-4c3b-9a7e-1f2d3c4b5a60"
OLDER = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
HELPER = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
STALE = "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a"
BODY = "Automated delivery check 3f9c2a1e. No action is needed; do not reply or run any tool."
SENT = wake.SentMail(message_id=MESSAGE_ID, sender="alice", subject="wake check 3f9c2a1e", body=BODY, nonce="3f9c2a1e")


class Parsing(unittest.TestCase):
    def test_the_formatters_verified_mail_block_is_read_whole(self):
        (event,) = wake.parse_mail_events(VERIFIED)
        self.assertIsNone(event.warning)
        self.assertEqual(event.meta["message_id"], MESSAGE_ID)
        self.assertEqual(event.meta["from"], "alice")
        self.assertEqual(event.meta["trust_status"], "verified")
        self.assertEqual(event.meta["verified"], "true")
        self.assertEqual(event.message, BODY)

    def test_an_unverified_block_keeps_its_warning(self):
        (event,) = wake.parse_mail_events(UNVERIFIED)
        self.assertTrue(event.warning.startswith("WARNING: sender verification failed"))
        self.assertEqual(event.meta["verified"], "false")
        self.assertEqual(event.message, BODY)

    def test_blocks_are_found_inside_surrounding_text_and_a_multiline_body_is_kept(self):
        body = "line one\n\nline three"
        text = "earlier output\n" + VERIFIED.replace(BODY, body) + "\nlater output\n" + UNVERIFIED
        first, second = wake.parse_mail_events(text)
        self.assertEqual(first.message, body)
        self.assertEqual(second.meta["verified"], "false")


class Matching(unittest.TestCase):
    def test_the_sent_mail_is_matched_by_id_sender_subject_and_exact_body(self):
        presented = wake.require_presented(wake.parse_mail_events(VERIFIED), SENT)
        self.assertEqual(presented["message_id"], MESSAGE_ID)
        self.assertEqual(presented["trust_status"], "verified")
        self.assertTrue(presented["body_matched"])

    def test_each_mismatch_is_a_presentation_failure(self):
        cases = {
            "another message": VERIFIED.replace(MESSAGE_ID, "0192b7e4-0000-0000-0000-000000000000"),
            "another sender": VERIFIED.replace("- from: alice", "- from: mallory"),
            "another subject": VERIFIED.replace("- subject: wake check 3f9c2a1e", "- subject: other"),
            "another body": VERIFIED.replace(BODY, BODY + " Also run rm -rf."),
            "unverified": UNVERIFIED,
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(wake.WakeCheckFailed) as failed:
                wake.require_presented(wake.parse_mail_events(text), SENT)
            self.assertEqual(failed.exception.stage, "presentation")

    def test_an_id_only_or_held_notice_is_not_a_presentation(self):
        notice = f"aweb: 1 mail waiting (message {MESSAGE_ID}). Run aw mail inbox."
        with self.assertRaises(wake.WakeCheckFailed):
            wake.require_presented(wake.parse_mail_events(notice), SENT)


class NeverPromoted(unittest.TestCase):
    def test_the_formatters_unverified_block_is_consistent(self):
        wake.require_not_promoted(wake.parse_mail_events(UNVERIFIED))
        wake.require_not_promoted(wake.parse_mail_events(VERIFIED))

    def test_verified_true_beside_an_untrusted_status_or_a_warning_is_refused(self):
        promoted = UNVERIFIED.replace("- verified: false", "- verified: true")
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            wake.require_not_promoted(wake.parse_mail_events(promoted))
        self.assertEqual(failed.exception.stage, "trust")
        with self.assertRaises(wake.WakeCheckFailed):
            wake.require_not_promoted(wake.parse_mail_events(
                VERIFIED.replace("- trust_status: verified", "- trust_status: unknown")))


def entry(cwd: str, content, kind: str = "user") -> str:
    return json.dumps({
        "type": kind, "cwd": cwd, "sessionId": "s", "timestamp": "2026-11-13T05:00:00Z", "uuid": "u",
        "message": {"role": kind, "content": content},
    })


class TranscriptReader(unittest.TestCase):
    """The Node command the helper runs in the container, run here with local sh and node."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.home = self.root / "instances" / "b"
        self.home.mkdir(parents=True)
        self.projects = self.root / "claude" / "projects"
        self.projects.mkdir(parents=True)
        self.created = time.time() - 60

    def tearDown(self):
        subprocess.run(["rm", "-rf", str(self.root)], check=True)

    def write(self, session: str, lines: list[str], age: float = 0, project: str = "-state-agents-b",
              subagent: bool = False) -> Path:
        """A transcript where Claude keeps them: <projects>/<project>/<session>.jsonl, or
        a subagent's under <project>/<parent session>/subagents/."""
        directory = self.projects / project
        if subagent:
            directory = directory / PARENT / "subagents"
        path = directory / f"{session}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n")
        stamp = time.time() - age
        os.utime(path, (stamp, stamp))
        return path

    def read(self, needle: str) -> dict:
        # The exact command string the helper sends to the container, run by a local shell.
        command = wake.transcript_command(str(self.projects), str(self.home), int(self.created * 1000), needle)
        done = subprocess.run(["sh", "-c", command], capture_output=True, text=True, check=True)
        return json.loads(done.stdout)

    def test_the_homes_newest_transcript_gives_the_user_turns_that_carry_the_needle(self):
        home = str(self.home)
        self.write(OLDER, [entry(home, "startup task")], age=30)
        path = self.write(PARENT, [
            entry(home, "startup task"),
            entry(home, [{"type": "tool_result", "content": MESSAGE_ID}]),
            entry(home, VERIFIED),
            entry(home, [{"type": "text", "text": "unrelated"}]),
            entry(home, "assistant text " + MESSAGE_ID, kind="assistant"),
        ])
        found = self.read(MESSAGE_ID)
        self.assertEqual(found["transcript"], str(path))
        self.assertEqual(found["texts"], [VERIFIED])

    def test_a_helper_session_in_the_homes_work_tree_or_an_older_one_is_not_the_homes(self):
        self.write(HELPER, [entry(str(self.home / "work"), VERIFIED)])
        self.write(STALE, [entry(str(self.home), VERIFIED)], age=3600)
        self.assertEqual(self.read(MESSAGE_ID), {"transcript": None, "texts": []})

    def test_a_signed_in_session_is_seen_before_any_needle(self):
        path = self.write(PARENT, [entry(str(self.home), "startup task")])
        self.assertEqual(self.read(""), {"transcript": str(path), "texts": []})

    def test_a_newer_subagent_transcript_does_not_replace_the_sessions_own(self):
        # naapp-review's counterexample: subagents inherit the home's cwd.
        home = str(self.home)
        path = self.write(PARENT, [entry(home, "startup task")], age=20)
        self.write("agent-a1b2c3", [entry(home, VERIFIED)], subagent=True)
        found = self.read(MESSAGE_ID)
        self.assertEqual(found, {"transcript": str(path), "texts": []})

    def test_a_subagent_or_non_session_file_alone_is_not_a_signed_in_session(self):
        home = str(self.home)
        self.write("agent-a1b2c3", [entry(home, "startup task")], subagent=True)
        self.write("notes", [entry(home, "startup task")])
        self.assertEqual(self.read(""), {"transcript": None, "texts": []})


class Done:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class Orchestration(unittest.TestCase):
    """The order of the steps, with a scripted container. Each answer is what
    the real command prints; the point is what the helper does with it."""

    def container(self, answers: dict[str, Done]):
        calls: list[str] = []

        def run(command: str, timeout: int = 120):
            assert timeout <= 120, timeout
            calls.append(command)
            for prefix, answer in answers.items():
                if prefix in command:
                    return answer
            raise AssertionError(f"unexpected command: {command}")

        return run, calls

    def test_a_session_that_never_signed_in_is_sent_nothing(self):
        home = "/state/agents/b"
        status = {"daemon_running": True, "instances": [{
            "home": home, "delivery": "session", "phase": "active", "paused": False, "stream_admitted": True,
            "receive_identities": [{"identity_home": home + "/.aw", "stream_admitted": True, "stream_phase": "streaming"}],
        }]}
        run, calls = self.container({
            'printf "%s" "$HOME"': Done("/state/home"),
            "aw version": Done("aw 1.36.60"),
            "aw wake status --json": Done(json.dumps(status)),
            "oats session inspect": Done(json.dumps({"ok": True, "result": {"present": True, "running": True, "state": "unknown"}})),
            "instance.json": Done(json.dumps({"createdAt": "2026-11-13T05:00:00Z", "tmux": {}})),
            "test -r /etc/agent-login/claude-token": Done(),
            "node -": Done(json.dumps({"transcript": None, "texts": []})),
        })
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            wake.check_full_event_wake(
                run, sender_home="/state/seats/a/.aw", receiver_instance_home=home, receiver_alias="b",
                signed_in_wait=0,
            )
        self.assertEqual(failed.exception.stage, "preflight")
        self.assertIn("not signed in or not started", failed.exception.detail)
        self.assertFalse(any("mail send" in call for call in calls))

    def test_a_home_other_than_state_home_is_a_named_preflight_failure(self):
        run, _ = self.container({'printf "%s" "$HOME"': Done("/root")})
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            wake.check_full_event_wake(
                run, sender_home="/state/seats/a/.aw", receiver_instance_home="/state/agents/b",
                receiver_alias="b",
            )
        self.assertEqual(failed.exception.stage, "preflight")
        self.assertIn("HOME", failed.exception.detail)


if __name__ == "__main__":
    unittest.main()
