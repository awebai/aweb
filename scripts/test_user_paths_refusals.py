"""Retained 1.36.40 command output must reach every refusal assertion.

The subprocess results below reproduce commands.json from run
vm-b1c617e336964189a86b8aa620c11f1d; they test the driver, not the server.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths import Lane  # noqa: E402


class ReleasedRefusals(unittest.TestCase):
    def lane(self, directory, result, *, legacy=True, policy="team_and_contacts"):
        lane = Lane.__new__(Lane)
        lane.name = "released" if legacy else "head"
        lane.version = "1.36.40" if legacy else "1.36.58"
        lane.legacy_released_diagnostics = legacy
        lane.root = Path(directory)
        lane.results = []
        lane.actors = {}
        for actor in ["t1", "g1", "g2", "nonresident", "remote"]:
            events = lane.root / (actor + "-events.jsonl")
            events.write_text("")
            lane.actors[actor] = dict(
                address="released-" + actor + ".test/" + actor, events=events
            )
        calls = []
        stored_policy = "open"

        def command(actor, *args, **kwargs):
            nonlocal stored_policy
            calls.append((actor, args, kwargs))
            if args[0] == "inbound-mode":
                if args[1:] == ("contacts-only",):
                    stored_policy = policy
                elif args[1:] == ("open",):
                    stored_policy = "open"
                else:
                    self.assertEqual(args, ("inbound-mode",))
                return dict(inbound_mode=stored_policy)
            if args[:2] in [("mail", "inbox"), ("chat", "pending")]:
                return []
            return result

        lane.command = command
        return lane, calls

    def response(self, kind, status, detail, reason=None):
        prefix = "sending message: " if kind == "chat" else ""
        body = dict(detail=detail)
        if reason is not None:
            body["reason"] = reason
        return subprocess.CompletedProcess(
            [], 1, "", prefix + f"aweb: http {status}: " + json.dumps(body) + "\n"
        )

    def test_six_observed_older_refusals_reach_no_delivery_checks(self):
        for kind in ["mail", "chat"]:
            cases = [
                (
                    "contacts-only",
                    "g2",
                    403,
                    "Recipient only accepts messages from verified team members or exact active contacts. Ask the recipient to add your exact address as a contact or check their inbound policy.",
                    "recipient_policy_rejected",
                ),
                (
                    "nonresident",
                    "nonresident",
                    None,
                    "agent not found: released-nonresident.test/nonresident",
                    None,
                ),
                (
                    "cross-server",
                    "remote",
                    422,
                    "Federated mail delivery to http://peer:8000 failed: local_sender_route_mismatch",
                    "local_sender_route_mismatch",
                ),
            ]
            for case, receiver, status, message, reason in cases:
                with (
                    self.subTest(case=case, kind=kind),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    result = (
                        self.response(kind, status, message, reason)
                        if status is not None
                        else subprocess.CompletedProcess([], 1, "", message + "\n")
                    )
                    lane, calls = self.lane(directory, result)
                    # These receipts start at the send. The policy setup and
                    # read-back are covered by the contacts-only gate controls.
                    lane.refused(
                        "g1" if case == "nonresident" else "t1",
                        receiver,
                        kind,
                        status,
                        message,
                        reason,
                    )
                    self.assertEqual(len(lane.results), 1)
                    receipt = json.loads(
                        (lane.root / f"refusal-{receiver}-{kind}.json").read_text()
                    )
                    self.assertEqual(receipt["exit"], 1)
                    self.assertEqual(receipt["stderr"], result.stderr)
                    self.assertEqual(receipt["response"].get("http_status"), status)
                    if receiver != "nonresident":
                        self.assertTrue(
                            any(
                                args[:2]
                                == (
                                    ("mail", "inbox")
                                    if kind == "mail"
                                    else ("chat", "pending")
                                )
                                for _, args, _ in calls
                            )
                        )

    def test_nonresident_controls_select_the_actual_13640_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            lane, _ = self.lane(directory, None)
            observed = []
            lane.run_case = lambda case, operation: (
                operation() if "/nonresident/" in case else None
            )
            lane.refused = lambda *args: observed.append(args)
            lane.controls()
            self.assertEqual(
                observed,
                [
                    (
                        "g1",
                        "nonresident",
                        kind,
                        None,
                        "agent not found: released-nonresident.test/nonresident",
                    )
                    for kind in ["mail", "chat"]
                ],
            )

    def test_head_keeps_its_structured_status_and_exact_policy(self):
        message = "Recipient only accepts messages from exact active contacts"
        result = subprocess.CompletedProcess(
            [],
            1,
            json.dumps(
                dict(
                    error=dict(
                        http_status=403,
                        message=message,
                        reason="recipient_policy_rejected",
                    )
                )
            ),
            "",
        )
        with tempfile.TemporaryDirectory() as directory:
            lane, _ = self.lane(directory, result, legacy=False, policy="contacts_only")
            lane.contacts_only("mail")
            self.assertEqual(len(lane.results), 1)
        with tempfile.TemporaryDirectory() as directory:
            lane, _ = self.lane(directory, result, legacy=False)
            with self.assertRaises(AssertionError):
                lane.contacts_only("mail")

    def test_wrong_exit_status_reason_or_transport_is_never_a_refusal(self):
        message = "local_sender_route_mismatch"
        good = self.response("chat", 422, message, message)
        variants = [
            subprocess.CompletedProcess([], 0, good.stdout, good.stderr),
            subprocess.CompletedProcess([], 2, good.stdout, good.stderr),
            subprocess.CompletedProcess([], 1, "{broken", good.stderr),
            self.response("chat", 503, message, message),
            self.response("chat", 422, "different refusal", "other_reason"),
            subprocess.CompletedProcess([], 1, "", "connection refused\n"),
            subprocess.CompletedProcess([], 1, "", good.stderr + "timeout\n"),
        ]
        for result in variants:
            with (
                self.subTest(result=result),
                tempfile.TemporaryDirectory() as directory,
            ):
                lane, _ = self.lane(directory, result)
                with self.assertRaises((AssertionError, ValueError)):
                    lane.refused("t1", "remote", "chat", 422, message, message)
                self.assertEqual(lane.results, [])

    def test_no_delivery_assertions_still_reject_a_delivered_refused_body(self):
        message = "local_sender_route_mismatch"
        with tempfile.TemporaryDirectory() as directory:
            lane, _ = self.lane(directory, self.response("chat", 422, message, message))
            command = lane.command

            def delivered(actor, *args, **kwargs):
                if args[:2] == ("chat", "pending"):
                    return [dict(body=lane.last_body)]
                lane.last_body = args[-1]
                return command(actor, *args, **kwargs)

            lane.command = delivered
            with self.assertRaises(AssertionError):
                lane.refused("t1", "remote", "chat", 422, message, message)
            self.assertEqual(lane.results, [])


if __name__ == "__main__":
    unittest.main()
