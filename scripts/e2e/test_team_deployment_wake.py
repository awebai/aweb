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


class ScriptedContainer(unittest.TestCase):
    """A scripted container. Each answer is what the real command prints; the
    point is what the helper does with it."""

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


class Orchestration(ScriptedContainer):
    """The order of the steps of the check that sends its own mail."""

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


SENDER_DID = "did:key:z6MkSender"
RECEIVER_DID = "did:key:z6MkReceiver"
CONVERSATION = "9f8fe9e5-3ad7-4bf0-9835-47e7e20267e5"
REPLY_ID = "0192b7e4-2222-7a3b-9e4f-5a6b7c8d9e0f"
RECEIVER_HOME = "/state/agents/b"
SENDER_HOME = "/state/seats/a/.aw"


def mail(message_id: str, from_did: str, to_did: str, created_at: str, *, body: str = "4",
         subject: str = "Re: wake check 3f9c2a1e", status: str = "verified", conversation: str = CONVERSATION) -> dict:
    """A message as aw mail show --json prints it."""
    aliases = {SENDER_DID: "alice", RECEIVER_DID: "b"}
    return {"message_id": message_id, "conversation_id": conversation, "from_alias": aliases.get(from_did, "mallory"),
            "from_did": from_did, "to_alias": aliases.get(to_did, "mallory"), "to_did": to_did, "subject": subject,
            "body": body, "created_at": created_at, "verification_status": status, "read_at": None}


SENT_JSON = mail(MESSAGE_ID, SENDER_DID, RECEIVER_DID, "2026-11-13T05:10:00.123456+00:00",
                 body=BODY, subject="wake check 3f9c2a1e")
REPLY_JSON = mail(REPLY_ID, RECEIVER_DID, SENDER_DID, "2026-11-13T05:11:00.5+00:00")
SESSION_CREATED_MS = 1794546000000  # 2026-11-13T05:00:00Z


def bind(shown: dict) -> wake.BoundMail:
    return wake.bind_sent_mail({"messages": [shown]}, message_id=MESSAGE_ID, sender_did=SENDER_DID,
                               receiver_dids={RECEIVER_DID}, receiver_alias="b", session_created_ms=SESSION_CREATED_MS)


class BindSentMail(unittest.TestCase):
    def test_the_mail_from_the_sender_to_the_receiver_after_the_session_started_is_bound(self):
        sent = bind(SENT_JSON)
        self.assertEqual((sent.message_id, sent.sender, sent.subject, sent.body), (MESSAGE_ID, "alice",
                                                                                   "wake check 3f9c2a1e", BODY))
        self.assertEqual((sent.conversation_id, sent.sender_did, sent.receiver_did),
                         (CONVERSATION, SENDER_DID, RECEIVER_DID))

    def test_a_qualified_sender_is_named_as_channel_core_presents_it(self):
        # channel-core's senderDisplayAddress: from_address when present, else from_alias.
        sent = bind({**SENT_JSON, "from_address": "example.com/alice"})
        self.assertEqual(sent.sender, "example.com/alice")
        presented = wake.require_presented(
            wake.parse_mail_events(VERIFIED.replace("- from: alice", "- from: example.com/alice")), sent)
        self.assertEqual(presented["from"], "example.com/alice")
        self.assertEqual(bind({**SENT_JSON, "from_address": "  "}).sender, "alice")

    def test_another_sender_recipient_or_a_mail_older_than_the_session_is_refused(self):
        cases = {
            "another sender": {**SENT_JSON, "from_did": "did:key:z6MkMallory"},
            "another recipient DID": {**SENT_JSON, "to_did": "did:key:z6MkOther"},
            "another recipient alias": {**SENT_JSON, "to_alias": "c"},
            "sent before the session": {**SENT_JSON, "created_at": "2026-11-13T04:59:59+00:00"},
            "another message": {**SENT_JSON, "message_id": REPLY_ID},
            "no conversation": {**SENT_JSON, "conversation_id": ""},
        }
        for name, shown in cases.items():
            with self.subTest(name), self.assertRaises(wake.WakeCheckFailed) as failed:
                bind(shown)
            self.assertEqual(failed.exception.stage, "sent")


class FindReply(unittest.TestCase):
    def test_the_receivers_first_later_reply_in_the_conversation_is_the_reply(self):
        later = mail("0192b7e4-3333-7a3b-9e4f-5a6b7c8d9e0f", RECEIVER_DID, SENDER_DID, "2026-11-13T05:12:00+00:00")
        found = wake.find_reply({"messages": [SENT_JSON, REPLY_JSON, later]}, bind(SENT_JSON))
        self.assertEqual(found["message_id"], REPLY_ID)
        self.assertEqual(found["body"], "4")
        self.assertEqual(found["verification_status"], "verified")
        self.assertEqual(found["later_replies"], 1)

    def test_unrelated_and_pre_existing_replies_are_not_the_reply(self):
        conversation = {"messages": [
            mail("0192b7e4-4444-7a3b-9e4f-5a6b7c8d9e0f", RECEIVER_DID, SENDER_DID, "2026-11-13T05:09:00+00:00"),
            SENT_JSON,
            mail("0192b7e4-5555-7a3b-9e4f-5a6b7c8d9e0f", "did:key:z6MkMallory", SENDER_DID,
                 "2026-11-13T05:11:00+00:00"),
            mail("0192b7e4-6666-7a3b-9e4f-5a6b7c8d9e0f", RECEIVER_DID, SENDER_DID, "2026-11-13T05:11:00+00:00",
                 conversation="0192b7e4-0000-0000-0000-000000000000"),
            mail("0192b7e4-7777-7a3b-9e4f-5a6b7c8d9e0f", RECEIVER_DID, "did:key:z6MkOther",
                 "2026-11-13T05:11:00+00:00"),
        ]}
        self.assertIsNone(wake.find_reply(conversation, bind(SENT_JSON)))

    def test_an_unverified_reply_from_the_receiver_is_a_trust_failure(self):
        conversation = {"messages": [SENT_JSON, {**REPLY_JSON, "verification_status": "unverified"}]}
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            wake.find_reply(conversation, bind(SENT_JSON))
        self.assertEqual(failed.exception.stage, "reply")

    def test_a_long_reply_body_is_capped(self):
        found = wake.find_reply({"messages": [SENT_JSON, {**REPLY_JSON, "body": "x" * 5000}]}, bind(SENT_JSON))
        self.assertEqual(len(found["body"]), wake.REPLY_BODY_LIMIT)
        self.assertTrue(found["body_truncated"])


class Correlation(ScriptedContainer):
    """The already-sent mail's wake and reply, with a scripted container."""

    def answers(self, conversation: list[dict], texts: list[str]) -> dict[str, Done]:
        status = {"daemon_running": True, "instances": [{
            "home": RECEIVER_HOME, "delivery": "session", "phase": "active", "paused": False,
            "receive_identities": [{"identity_home": RECEIVER_HOME + "/.aw", "stream_admitted": True,
                                    "stream_phase": "streaming"}],
        }]}
        return {
            'printf "%s" "$HOME"': Done("/state/home"),
            "aw version": Done("aw 1.36.60"),
            "aw wake status --json": Done(json.dumps(status)),
            "oats session inspect": Done(json.dumps({"ok": True, "result": {"present": True, "state": "idle"}})),
            "instance.json": Done(json.dumps({"createdAt": "2026-11-13T05:00:00Z", "tmux": {}})),
            "test -r /etc/agent-login/claude-token": Done(),
            "node -": Done(json.dumps({"transcript": "/state/home/.claude/projects/p/s.jsonl", "texts": texts})),
            f"{SENDER_HOME} --json whoami": Done(json.dumps({"alias": "alice", "did": SENDER_DID})),
            f"{RECEIVER_HOME}/.aw --json whoami": Done(json.dumps({"alias": "b", "did": RECEIVER_DID})),
            "mail show --message-id": Done(json.dumps({"messages": [SENT_JSON]})),
            "mail show --conversation-id": Done(json.dumps({"messages": conversation})),
        }

    def correlate(self, run):
        return wake.correlate_mail_wake(run, message_id=MESSAGE_ID, sender_home=SENDER_HOME,
                                        receiver_instance_home=RECEIVER_HOME, receiver_alias="b",
                                        timeout=0, reply_timeout=0, signed_in_wait=0, poll=0)

    def test_the_sent_mail_its_wake_and_its_reply_are_one_receipt_and_nothing_is_sent(self):
        run, calls = self.container(self.answers([SENT_JSON, REPLY_JSON], [VERIFIED]))
        receipt = self.correlate(run)
        self.assertEqual(receipt["sent"]["message_id"], MESSAGE_ID)
        self.assertEqual(receipt["sent"]["conversation_id"], CONVERSATION)
        self.assertEqual(receipt["presented"]["trust_status"], "verified")
        self.assertEqual(receipt["evidence"]["block"], VERIFIED)
        self.assertEqual(receipt["reply"]["message_id"], REPLY_ID)
        self.assertFalse(any("mail send" in call or "mail inbox" in call or "mail ack" in call for call in calls))

    def test_no_reply_by_the_deadline_keeps_what_was_seen_and_invents_no_reply(self):
        run, _ = self.container(self.answers([SENT_JSON], [VERIFIED]))
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            self.correlate(run)
        self.assertEqual(failed.exception.stage, "reply")
        partial = failed.exception.partial
        self.assertEqual(partial["sent"]["message_id"], MESSAGE_ID)
        self.assertEqual(partial["presented"]["message_id"], MESSAGE_ID)
        self.assertNotIn("reply", partial)

    def test_a_mail_that_does_not_bind_keeps_the_preflight_and_nothing_else(self):
        answers = self.answers([SENT_JSON, REPLY_JSON], [VERIFIED])
        answers["mail show --message-id"] = Done(json.dumps({"messages": [{**SENT_JSON, "to_alias": "c"}]}))
        run, _ = self.container(answers)
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            self.correlate(run)
        self.assertEqual(failed.exception.stage, "sent")
        self.assertEqual(set(failed.exception.partial), {"preflight"})

    def test_a_failed_or_unreadable_conversation_read_keeps_the_proved_wake(self):
        for name, answer in {"exit 1": Done(returncode=1, stderr="server error"), "not JSON": Done("<html>")}.items():
            answers = self.answers([], [VERIFIED])
            answers["mail show --conversation-id"] = answer
            run, _ = self.container(answers)
            with self.subTest(name), self.assertRaises(wake.WakeCheckFailed) as failed:
                self.correlate(run)
            self.assertEqual(failed.exception.stage, "reply")
            self.assertEqual(failed.exception.partial["presented"]["message_id"], MESSAGE_ID)
            self.assertIn("evidence", failed.exception.partial)
            self.assertNotIn("reply", failed.exception.partial)

    def test_no_wake_by_the_deadline_keeps_the_bound_mail_and_invents_no_wake(self):
        run, _ = self.container(self.answers([SENT_JSON, REPLY_JSON], []))
        with self.assertRaises(wake.WakeCheckFailed) as failed:
            self.correlate(run)
        self.assertEqual(failed.exception.stage, "presentation")
        self.assertEqual(failed.exception.partial["sent"]["message_id"], MESSAGE_ID)
        self.assertNotIn("presented", failed.exception.partial)

    def test_preflight_only_reads_the_session_and_sends_nothing(self):
        run, calls = self.container(self.answers([], []))
        result = wake.preflight_only(run, receiver_instance_home=RECEIVER_HOME, signed_in_wait=0, poll=0)
        self.assertEqual(result["transcript"], "/state/home/.claude/projects/p/s.jsonl")
        self.assertNotIn("tmux", result)
        self.assertFalse(any(" mail " in call for call in calls))


class FailureOutput(unittest.TestCase):
    def test_a_failure_prints_its_stage_and_detail_and_any_partial_receipt(self):
        self.assertEqual(wake.failure_output(wake.WakeCheckFailed("preflight", "no login")),
                         {"failed": "preflight", "detail": "no login"})
        partial = {"sent": {"message_id": MESSAGE_ID}}
        self.assertEqual(wake.failure_output(wake.WakeCheckFailed("reply", "none", partial)),
                         {"failed": "reply", "detail": "none", "partial": partial})


if __name__ == "__main__":
    unittest.main()
