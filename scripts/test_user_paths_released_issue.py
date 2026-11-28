"""The reviewed actw allowance keeps its exact historical failure and scope."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths import CLICommandError, Lane  # noqa: E402
from user_paths_result import classify_outcome, qualification  # noqa: E402

MESSAGE = (
    "sending message: recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel "
    "and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext"
)
SESSION = "b58ac09b-d7b0-4c70-afe3-1daf87e57cb4"


def failure(case):
    sender, receiver = case.split("/")[1].split("->")
    return dict(
        case=case,
        status="FAILED",
        failure=dict(
            actor=sender,
            args=[
                "chat",
                "send-and-wait",
                receiver,
                case + "/" + "a" * 32,
                "--e2ee",
                "--wait",
                "0",
            ],
            exit=1,
            stdout="",
            response=None,
            stderr=MESSAGE + "\n",
            phase="initial-send",
            existing_local_session=SESSION,
        ),
    )


class HistoricalChatIssue(unittest.TestCase):
    def test_both_exact_older_cases_are_known_failures_not_passes(self):
        for case in ["released/t1->t2/chat/v2", "released/t2->t1/chat/v2"]:
            for version in ["1.36.40", "1.36.41", "1.36.53", "1.36.54"]:
                with self.subTest(case=case, version=version):
                    row = classify_outcome(failure(case), version)
                    self.assertEqual(row["status"], "KNOWN_ISSUE")
                    self.assertEqual(row["observed_status"], "FAILED")
                    self.assertEqual(row["known_issue"]["task"], "aweb-actw")
                    self.assertEqual(classify_outcome(row, version), row)
                    self.assertEqual(
                        classify_outcome(dict(case=case, status="PASSED"), version)[
                            "status"
                        ],
                        "FAILED",
                    )

    def test_no_other_version_lane_command_or_failure_gets_the_allowance(self):
        case = "released/t1->t2/chat/v2"
        original = failure(case)
        for version in ["1.36.39", "1.36.55", "1.36.58", "dev", "1.36.54-rc.1", None]:
            with self.subTest(version=version):
                self.assertEqual(
                    classify_outcome(original, version)["status"], "FAILED"
                )
        for version in ["1.36.39", "1.36.55", "1.36.58"]:
            self.assertEqual(
                classify_outcome(dict(case=case, status="PASSED"), version)["status"],
                "PASSED",
            )
        variants = []
        for field, value in [
            ("exit", 2),
            ("phase", "reply"),
            ("phase", None),
            ("existing_local_session", None),
            ("stdout", "{broken"),
            ("stderr", MESSAGE + " (server refusal)\n"),
            ("actor", "t2"),
            ("args", ["chat", "send", "--session-id", SESSION, "--e2ee"]),
            ("response", {"error": {"code": "permission_denied", "message": MESSAGE}}),
        ]:
            row = copy.deepcopy(original)
            row["failure"][field] = value
            variants.append((field, row))
        for field, row in variants:
            with self.subTest(field=field):
                self.assertEqual(classify_outcome(row, "1.36.40")["status"], "FAILED")
        for case in [
            "head/t1->t2/chat/v2",
            "released/g1->t1/chat/v2",
            "released/t1->t2/mail/v2",
        ]:
            row = copy.deepcopy(original)
            row["case"] = case
            self.assertEqual(classify_outcome(row, "1.36.40")["status"], "FAILED")

    def test_raw_failed_command_keeps_stdout_and_phase_evidence(self):
        result = subprocess.CompletedProcess([], 1, "", MESSAGE + "\n")
        error = CLICommandError(
            "released", "t1", ["chat"], result, phase="initial-send"
        )
        self.assertEqual(error.failure["stdout"], "")
        self.assertIsNone(error.failure["response"])
        self.assertEqual(error.failure["phase"], "initial-send")

    def test_parent_keeps_known_failures_out_of_passed_case_count(self):
        inventory = qualification({}, 10, [])["required_agent_cases"]
        lanes = {
            name: dict(
                version="1.36.40" if name == "released" else "dev",
                outcomes=[
                    dict(case=case, status="PASSED")
                    for case in inventory
                    if case.startswith(name + "/")
                ],
            )
            for name in ["head", "released"]
        }
        for row in lanes["released"]["outcomes"]:
            if row["case"] in ["released/t1->t2/chat/v2", "released/t2->t1/chat/v2"]:
                row.update(failure(row["case"]))
            elif row["case"] in [
                "released/contacts-only/mail",
                "released/contacts-only/chat",
            ]:
                diagnostic = "Expected contacts_only; server stored team_and_contacts"
                row.update(status="FAILED", error=diagnostic, assertion=diagnostic)
        report = qualification(lanes, 100, [])
        self.assertEqual(report["status"], "PASSED")
        known_issues = {row["case"] for row in report["known_issues"]}
        self.assertEqual(
            known_issues,
            {
                "released/t1->t2/chat/v2",
                "released/t2->t1/chat/v2",
                "released/contacts-only/mail",
                "released/contacts-only/chat",
            },
        )
        # Known issues stay out of the passed count; everything else passed.
        self.assertEqual(
            set(report["passed_agent_cases"]), set(inventory) - known_issues
        )
        self.assertTrue(known_issues.isdisjoint(report["passed_agent_cases"]))
        self.assertEqual(set(report["required_agent_cases"]), set(inventory))
        self.assertEqual(report["missing_agent_cases"], [])

    def test_public_diagnostics_require_existing_local_session_and_both_keys(self):
        case = "released/t1->t2/chat/v2"
        with tempfile.TemporaryDirectory() as directory:
            lane = Lane.__new__(Lane)
            lane.root = Path(directory)
            lane.results = ["released/t1->t2/chat/plain"]
            lane.actors = {
                name: dict(address="", did="did:key:" + name) for name in ["t1", "t2"]
            }
            roster = dict(
                agents=[
                    dict(
                        did_key="did:key:" + name,
                        identity_scope="local",
                        encryption_key=dict(version="aweb-e2ee-key-v1"),
                    )
                    for name in ["t1", "t2"]
                ]
            )
            sessions = dict(
                sessions=[dict(session_id=SESSION, participant_dids=["did:key:t2"])]
            )

            def command(actor, *args, **kwargs):
                data = (
                    roster
                    if len(args) > 3 and args[3].endswith("/v1/agents")
                    else sessions
                )
                return subprocess.CompletedProcess([], 0, json.dumps(data), "")

            lane.command = command
            with patch.dict(os.environ, {"USER_PATHS_COMPARISON_BIN": ""}):
                self.assertEqual(
                    lane.capture_failure(case, "t1", "t2", "chat", True), SESSION
                )
                lane.results = []
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))
                lane.results = ["released/t1->t2/chat/plain"]
                roster["agents"][1]["encryption_key"] = None
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))
                roster["agents"][1]["encryption_key"] = {"version": "aweb-e2ee-key-v1"}
                roster["agents"][1]["identity_scope"] = "global"
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))
                roster["agents"][1]["identity_scope"] = "local"
                sessions["sessions"] *= 2
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))
                sessions["sessions"] = [
                    dict(session_id=SESSION, participant_dids=["did:key:other"])
                ]
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))
                sessions["sessions"] = []
                self.assertIsNone(lane.capture_failure(case, "t1", "t2", "chat", True))


if __name__ == "__main__":
    unittest.main()
