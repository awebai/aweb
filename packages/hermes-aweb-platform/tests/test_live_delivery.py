"""Real gateway acceptance probes, each in a fresh process/home.

Uses the same opt-in local fixtures as test_live_chat.py. Timing/fault probes
observe or delay completed real CLI operations; no replacement CLI, server,
adapter, model or fabricated event payload is installed. Ordinary-turn entry
observers forward to the real handler, and prompt checks use real Hermes primitives.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

REQUIRED = ("HERMES_AGENT_SOURCE", "HERMES_LIVE_RECEIVER_HOME",
            "HERMES_LIVE_SENDER_HOME", "HERMES_LIVE_POSTGRES_CONTAINER")


@unittest.skipUnless(all(os.environ.get(k) for k in REQUIRED), "requires local real-stack fixtures")
class LiveDeliveryTests(unittest.TestCase):
    def probe(self, case):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("live_delivery_probe.py")), case],
            text=True, capture_output=True, timeout=240 if case == "team" else 65,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        receipts = []
        for line in (result.stdout + "\n" + result.stderr).splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and ("case" in value or "upstream_hermes" in value):
                receipts.append(value)
                print(json.dumps(value))
        self.assertTrue(any(r.get("case") == case for r in receipts),
                        "probe exited without completing acceptance assertions: " + result.stderr[-12000:])

    def test_clarify_refusal_and_ordered_content(self):
        self.probe("clarify")

    def test_empty_history_hint(self):
        self.probe("hint")

    def test_mail_fetch_retry(self):
        self.probe("mail_retry")

    def test_mail_reply_routes(self):
        self.probe("mail_routes")

    def test_first_contact_notice_explains_local_home_setup(self):
        self.probe("home_notice")

    def test_strict_team_intake(self):
        self.probe("team")

    def test_stream_health(self):
        self.probe("health")

    def test_aweb_cannot_resolve_approval_or_receive_prompt(self):
        self.probe("approval")

    def test_stop_is_content_and_shutdown_stays_unread(self):
        self.probe("stop")

    @unittest.skipUnless(os.environ.get("HERMES_LIVE_UNAUTHORIZED_HOME"), "requires unauthorized sender fixture")
    def test_unauthorized_mail_stays_unread(self):
        self.probe("unauthorized")
