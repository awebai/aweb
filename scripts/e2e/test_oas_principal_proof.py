from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from oas_principal_proof import (
    assert_resident_session,
    assert_unchanged,
    capture_structure,
    scan_instance,
    scan_sensitive_material,
    write_snapshot,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
GIT_COMMON_DIR = subprocess.check_output(
    ["git", "rev-parse", "--git-common-dir"], cwd=REPO_ROOT, text=True
).strip()
PINNED_OAS_ROOT = (REPO_ROOT / GIT_COMMON_DIR / "../../oas").resolve()


class PrincipalProofHarnessTests(unittest.TestCase):
    def test_default_suite_runs_proof_helper_tests(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        match = re.search(r"^test\s*:(.*)$", makefile, re.MULTILINE)
        self.assertIsNotNone(match, "Makefile has no default test target")
        self.assertIn("test-oas-proof-helpers", match.group(1).split())

    def test_customer_journey_wires_external_acquisition_and_distinct_operations(self) -> None:
        harness = (REPO_ROOT / "scripts/e2e-oas-attached-principal-retire.sh").read_text(encoding="utf-8")
        for required in (
            'install "$CAPABILITY_SOURCE" --dir "$FIXTURE_REPO"',
            'doctor "$FIXTURE_REPO" --soul proof-worker',
            'assert_owning_state_same refusal-before "refusal-after-$refused_mode"',
            'assert_pre_activation_state',
            'config-divergence',
            'divergent attach-existing setting did not produce its predicted binding mode',
            'PI_AGENT_HOME="$VICTIM_HOME" run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT"',
            'aweb-identity status --soul proof-worker',
            'assert_worker_doctor_state',
            'capture_operation_grants both-active "$VICTIM_OPERATION=0" "$ATTACKER_OPERATION=0"',
            'capture_operation_grants interrupted-grant "$INTERRUPTED_OPERATION=1"',
            'assert_operation_grant_isolation interrupted-grant interrupted-grant-recovered',
            'assert_clean_git_subject',
            'capture_execution_subject',
            'scan_provisioned_sensitive_material',
            'scan_final_known_material',
            'independent developers did not exercise duplicate local instance names',
            'duplicate local names collapsed into one provisioning operation',
            'attacker-after-victim-retire',
            'assert_durable_operation_tuple_same attacker-before-victim-cleanup attacker-after-victim-cleanup',
            'assert_durable_operation_tuple_same reverse-a-before-b-cleanup reverse-a-after-b-cleanup',
            'assert_durable_operation_tuple_same reverse-b-before-a-cleanup reverse-b-after-a-cleanup',
            'third failed cleanup did not enter terminal visible quarantine',
            '--retry-quarantine "$QUARANTINE_OPERATION"',
            'credential content scan excludes verbatim known file bytes but not encoded, split, derived',
            'refusal_temporal_claim_bounded_by_missing_local_allocation_counter',
        ):
            self.assertIn(required, harness)

    def test_harness_make_targets_pin_the_declared_oas_checkout(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        for target_name in ("test-oas-attached-principal-e2e", "test-oas-pi-resident-e2e"):
            target = re.search(
                rf"^{target_name}:.*\n\t([^\n]+)$",
                makefile,
                re.MULTILINE,
            )
            self.assertIsNotNone(target, f"Makefile has no {target_name} recipe")
            self.assertIn('OAS_TEST_ROOT="$(OAS_TEST_ROOT)"', target.group(1))

    def test_harness_preflight_checks_repository_paths_without_tooling(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "scripts/e2e-oas-attached-principal-retire.sh", "--preflight"],
            cwd=REPO_ROOT,
            env={"PATH": "/usr/bin:/bin", "OAS_TEST_ROOT": str(PINNED_OAS_ROOT)},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_harness_preflight_refuses_unattributed_oas_fallback(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "scripts/e2e-oas-attached-principal-retire.sh", "--preflight"],
            cwd=REPO_ROOT,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OAS_TEST_ROOT must name the reviewed OAS checkout", result.stderr)

    def test_harness_preflight_refuses_aw_binary_override(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "scripts/e2e-oas-attached-principal-retire.sh", "--preflight"],
            cwd=REPO_ROOT,
            env={"PATH": "/usr/bin:/bin", "AW_BIN": "/tmp/unattributed-aw"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AW_BIN overrides are outside the declared execution subject", result.stderr)

    def test_harness_preflight_refuses_external_node_preloads(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "scripts/e2e-oas-attached-principal-retire.sh", "--preflight"],
            cwd=REPO_ROOT,
            env={
                "PATH": "/usr/bin:/bin",
                "NODE_OPTIONS": "--import=/tmp/external-preload.mjs",
                "OAS_TEST_ROOT": str(PINNED_OAS_ROOT),
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NODE_OPTIONS preloads are outside the declared execution subject", result.stderr)

    def test_bounded_branches_cannot_emit_broader_claim_wording(self) -> None:
        paths = (
            REPO_ROOT / "scripts/e2e-oas-attached-principal-retire.sh",
            REPO_ROOT / "scripts/e2e/oas_principal_proof.py",
            REPO_ROOT / "oas/.agents/capabilities/owned/aweb-identity-attach/PROVISIONING.md",
        )
        text = "\n".join(path.read_text(encoding="utf-8") for path in paths).lower()
        for forbidden in (
            "known non-secret",
            "secret-free",
            "no matching usable grant",
            "pure acquisition",
            "refused_before_create",
            "refused before create",
            "zero usable",
            '"oas_kernel_sha"',
        ):
            self.assertNotIn(forbidden, text)


class ResidentSessionEvidenceTests(unittest.TestCase):
    ADDRESS = "proof.local/resident"
    STABLE_ID = "did:aw:2ResidentProof"
    MESSAGE_ID = "message-proof-123"
    WAKE_BODY = "WAKE_PROOF_SENTINEL"
    REPLY_BODY = "REPLY_PROOF_SENTINEL"
    READY_SUBJECT = "OAS_RESIDENT_READY"
    READY_BODY = "READY_FROM_THROWAWAY_RESIDENT"
    SESSION_CWD = "/proof/instance"
    PROVIDER = "openai-codex"
    MODEL = "gpt-5.4-mini"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.session = Path(self.temporary.name) / "session.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_session(
        self, *, include_reply: bool = True, wake_before_ready: bool = False,
        fabricated_identity_fallback: bool = False,
    ) -> None:
        entries = [
            {"type": "session", "version": 3, "id": "session-proof", "cwd": self.SESSION_CWD},
            {
                "type": "message",
                "id": "assistant-whoami",
                "message": {
                    "role": "assistant",
                    "content": [{
                        "type": "toolCall",
                        "id": "call-whoami",
                        "name": "bash",
                        "arguments": {"command": (
                            "aw whoami --json || printf "
                            "'{\"address\":\"proof.local/resident\",\"stable_id\":\"did:aw:2ResidentProof\"}'"
                            if fabricated_identity_fallback else "aw whoami --json"
                        )},
                    }],
                    "provider": self.PROVIDER,
                    "model": self.MODEL,
                    "stopReason": "toolUse",
                },
            },
            {
                "type": "message",
                "id": "result-whoami",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "call-whoami",
                    "toolName": "bash",
                    "isError": False,
                    "content": [{
                        "type": "text",
                        "text": '{"address":"proof.local/resident","stable_id":"did:aw:2ResidentProof"}',
                    }],
                },
            },
            {
                "type": "message",
                "id": "assistant-ready",
                "message": {
                    "role": "assistant",
                    "content": [{
                        "type": "toolCall",
                        "id": "call-ready",
                        "name": "bash",
                        "arguments": {
                            "command": (
                                "aw mail send --plaintext --to observer "
                                f"--subject '{self.READY_SUBJECT}' --body '{self.READY_BODY}' --json"
                            ),
                        },
                    }],
                    "provider": self.PROVIDER,
                    "model": self.MODEL,
                    "stopReason": "toolUse",
                },
            },
            {
                "type": "message",
                "id": "result-ready",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "call-ready",
                    "toolName": "bash",
                    "isError": False,
                    "content": [{"type": "text", "text": "Sent mail"}],
                },
            },
            {
                "type": "message",
                "id": "assistant-settled",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Ready and waiting."}],
                    "provider": self.PROVIDER,
                    "model": self.MODEL,
                    "stopReason": "stop",
                },
            },
            {
                "type": "custom_message",
                "id": "wake-message",
                "customType": "aweb-channel",
                "content": f"aweb mail event received: {self.WAKE_BODY}",
                "details": {
                    "type": "mail",
                    "message_id": self.MESSAGE_ID,
                    "trust_status": "verified",
                    "verified": True,
                },
            },
        ]
        if wake_before_ready:
            wake = entries.pop()
            entries.insert(2, wake)
        if include_reply:
            entries.extend([
                {
                    "type": "message",
                    "id": "assistant-reply",
                    "message": {
                        "role": "assistant",
                        "content": [{
                            "type": "toolCall",
                            "id": "call-reply",
                            "name": "bash",
                            "arguments": {
                                "command": (
                                    f"aw mail reply {self.MESSAGE_ID} "
                                    f"--body '{self.REPLY_BODY}'"
                                ),
                            },
                        }],
                        "provider": self.PROVIDER,
                        "model": self.MODEL,
                        "stopReason": "toolUse",
                    },
                },
                {
                    "type": "message",
                    "id": "result-reply",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "call-reply",
                        "toolName": "bash",
                        "isError": False,
                        "content": [{"type": "text", "text": "Sent mail reply"}],
                    },
                },
            ])
        self.session.write_text(
            "".join(json.dumps(entry) + "\n" for entry in entries),
            encoding="utf-8",
        )

    def assert_session(self) -> dict[str, object]:
        return assert_resident_session(
            str(self.session),
            expected_address=self.ADDRESS,
            expected_stable_id=self.STABLE_ID,
            expected_message_id=self.MESSAGE_ID,
            expected_wake_body=self.WAKE_BODY,
            expected_reply_body=self.REPLY_BODY,
            expected_ready_subject=self.READY_SUBJECT,
            expected_ready_body=self.READY_BODY,
            expected_session_cwd=self.SESSION_CWD,
            expected_provider=self.PROVIDER,
            expected_model=self.MODEL,
        )

    def test_observes_identity_wake_and_successful_reply_inside_resident_session(self) -> None:
        self.write_session()
        observation = self.assert_session()
        self.assertEqual(observation["wake_message_id"], self.MESSAGE_ID)
        self.assertEqual(observation["identity"], {
            "address": self.ADDRESS,
            "stable_id": self.STABLE_ID,
        })
        self.assertEqual(observation["reply_tool_call_id"], "call-reply")
        self.assertEqual(observation["session_cwd"], self.SESSION_CWD)
        self.assertEqual(observation["model"], {
            "provider": self.PROVIDER,
            "model": self.MODEL,
        })

    def test_missing_reply_tool_call_is_reported_as_absent(self) -> None:
        self.write_session(include_reply=False)
        with self.assertRaisesRegex(AssertionError, "resident session has no matching reply tool call"):
            self.assert_session()

    def test_wake_before_resident_readiness_is_not_wake_evidence(self) -> None:
        self.write_session(wake_before_ready=True)
        with self.assertRaisesRegex(AssertionError, "wake was not observed after resident readiness settled"):
            self.assert_session()

    def test_chained_fallback_cannot_fabricate_process_identity(self) -> None:
        self.write_session(fabricated_identity_fallback=True)
        with self.assertRaisesRegex(AssertionError, "no exact ordinary aw whoami --json tool call"):
            self.assert_session()


class PrincipalProofFilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.principal = self.root / "principal"
        self.credentials = self.principal / "credentials"
        self.state = self.principal / "state"
        self.credentials.mkdir(parents=True)
        self.state.mkdir()
        self.key = self.credentials / "signing.key"
        self.key.write_bytes(b"throwaway-secret-key-material\n")
        (self.state / "state.json").write_text('{"durable":true}\n', encoding="utf-8")
        self.snapshot = self.root / "snapshot.json"
        write_snapshot(str(self.principal), str(self.snapshot))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def instance(self, name: str) -> Path:
        path = self.root / name
        path.mkdir()
        (path / "ordinary.txt").write_text("instance-only\n", encoding="utf-8")
        return path

    def test_snapshot_requires_bytes_paths_and_inodes_to_remain_unchanged(self) -> None:
        assert_unchanged(str(self.principal), str(self.snapshot))
        self.key.write_bytes(b"changed\n")
        with self.assertRaisesRegex(AssertionError, "principal store changed"):
            assert_unchanged(str(self.principal), str(self.snapshot))

    def test_snapshot_rejects_a_principal_store_symlink(self) -> None:
        os.symlink(self.key, self.state / "linked-key")
        with self.assertRaisesRegex(ValueError, "principal store contains a symbolic link"):
            write_snapshot(str(self.principal), str(self.root / "unsafe-snapshot.json"))

    def test_structure_capture_detects_same_byte_symlink_directory_and_type_changes(self) -> None:
        target = self.root / "target"
        target.mkdir()
        key = target / "signing.key"
        key.write_bytes(b"credential material")
        before = capture_structure(str(target))

        external = self.root / "external.key"
        external.write_bytes(key.read_bytes())
        key.unlink()
        key.symlink_to(external)
        (target / "added-directory").mkdir()
        after = capture_structure(str(target))
        self.assertNotEqual(before, after)
        row = next(entry for entry in after if entry["path"] == "signing.key")
        self.assertEqual(row["kind"], "symlink")
        self.assertEqual(row["target"], str(external))
        self.assertTrue(any(entry["path"] == "added-directory" for entry in after))

    def test_structure_capture_detects_mode_change(self) -> None:
        target = self.root / "mode-target"
        target.mkdir()
        key = target / "signing.key"
        key.write_bytes(b"credential material")
        before = capture_structure(str(target))
        key.chmod(0o600)
        after = capture_structure(str(target))
        self.assertNotEqual(before, after)

    def test_scan_accepts_an_unrelated_instance(self) -> None:
        scan_instance(str(self.snapshot), str(self.instance("clean-instance")))

    def test_scan_rejects_dot_aw_at_any_depth(self) -> None:
        instance = self.instance("dot-aw-instance")
        (instance / "nested" / ".aw").mkdir(parents=True)
        with self.assertRaisesRegex(AssertionError, "forbidden .aw"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_renamed_content_copy(self) -> None:
        instance = self.instance("copy-instance")
        (instance / "innocent.bin").write_bytes(self.key.read_bytes())
        with self.assertRaisesRegex(AssertionError, "principal file content"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_hardlink(self) -> None:
        instance = self.instance("hardlink-instance")
        os.link(self.key, instance / "ordinary-cache")
        with self.assertRaisesRegex(AssertionError, "principal hardlink"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_renamed_symlink_to_exact_principal_root(self) -> None:
        instance = self.instance("symlink-instance")
        os.symlink(self.principal, instance / "ordinary-directory", target_is_directory=True)
        with self.assertRaisesRegex(AssertionError, "symlink resolves into principal store"):
            scan_instance(str(self.snapshot), str(instance))

    def test_sensitive_scan_accepts_bounded_runtime_state_leaves(self) -> None:
        instance = self.instance("runtime-state-instance")
        runtime = instance / ".aw"
        runtime.mkdir()
        (runtime / "interaction-log.jsonl").write_text(
            '{"ts":"2026-01-01T00:00:00Z","kind":"mail_in","message_id":"message-1","text":"hello"}\n', encoding="utf-8"
        )
        (runtime / "channel-delivered-ids.json").write_text(
            '{"conversation-1":"message-1"}\n', encoding="utf-8"
        )
        scan_sensitive_material(str(self.snapshot), str(instance))

        (runtime / "signing.key").write_text("different bytes\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "unexpected .aw path"):
            scan_sensitive_material(str(self.snapshot), str(instance))

    def test_sensitive_scan_rejects_embedded_authority_bytes_in_interaction_log(self) -> None:
        instance = self.instance("tainted-interaction-instance")
        interaction = instance / ".aw" / "interaction-log.jsonl"
        interaction.parent.mkdir()
        interaction.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00Z", "kind": "mail_in", "text": f"prefix-{self.key.read_text()}-suffix"}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AssertionError, "embeds principal file bytes"):
            scan_sensitive_material(str(self.snapshot), str(instance))

    def test_sensitive_scan_rejects_embedded_authority_bytes_in_delivery_store(self) -> None:
        instance = self.instance("tainted-delivery-instance")
        delivery = instance / ".aw" / "channel-delivered-ids.json"
        delivery.parent.mkdir()
        delivery.write_text(
            json.dumps({"conversation-1": f"prefix-{self.key.read_text()}-suffix"}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AssertionError, "embeds principal file bytes"):
            scan_sensitive_material(str(self.snapshot), str(instance))

    def test_sensitive_scan_rejects_interaction_log_symlink(self) -> None:
        instance = self.instance("interaction-symlink-instance")
        runtime = instance / ".aw"
        runtime.mkdir()
        external = self.root / "external.jsonl"
        external.write_text('{"ts":"2026-01-01T00:00:00Z","kind":"mail_in","text":"hello"}\n', encoding="utf-8")
        (runtime / "interaction-log.jsonl").symlink_to(external)
        with self.assertRaisesRegex(AssertionError, "runtime state must be a regular file"):
            scan_sensitive_material(str(self.snapshot), str(instance))

    def test_sensitive_scan_rejects_delivery_store_symlink(self) -> None:
        instance = self.instance("delivery-symlink-instance")
        runtime = instance / ".aw"
        runtime.mkdir()
        external = self.root / "external.json"
        external.write_text('{}\n', encoding="utf-8")
        (runtime / "channel-delivered-ids.json").symlink_to(external)
        with self.assertRaisesRegex(AssertionError, "runtime state must be a regular file"):
            scan_sensitive_material(str(self.snapshot), str(instance))

    def test_sensitive_scan_rejects_unbounded_runtime_state_shapes(self) -> None:
        interaction_instance = self.instance("interaction-shape-instance")
        interaction = interaction_instance / ".aw" / "interaction-log.jsonl"
        interaction.parent.mkdir()
        interaction.write_text('{"authority":"unexpected"}\n', encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "unbounded shape"):
            scan_sensitive_material(str(self.snapshot), str(interaction_instance))

        interaction.write_text(
            '{"ts":"2026-01-01T00:00:00Z","kind":"mail_in","text":{"bearer":"nested"}}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AssertionError, "non-string or empty values"):
            scan_sensitive_material(str(self.snapshot), str(interaction_instance))

        interaction.write_text('{"kind":"mail_in","text":"hello"}\n', encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "lacks required discriminators"):
            scan_sensitive_material(str(self.snapshot), str(interaction_instance))

        interaction.write_text(
            '{"ts":"2026-01-01T00:00:00Z","kind":"unknown","text":"hello"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(AssertionError, "unknown kind"):
            scan_sensitive_material(str(self.snapshot), str(interaction_instance))

        delivery_instance = self.instance("delivery-shape-instance")
        delivery = delivery_instance / ".aw" / "channel-delivered-ids.json"
        delivery.parent.mkdir()
        delivery.write_text('{"conversation-1":["message-1"]}\n', encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "not a string map"):
            scan_sensitive_material(str(self.snapshot), str(delivery_instance))

    def test_sensitive_scan_rejects_oversized_runtime_state(self) -> None:
        instance = self.instance("oversized-runtime-state-instance")
        interaction = instance / ".aw" / "interaction-log.jsonl"
        interaction.parent.mkdir()
        interaction.write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaisesRegex(AssertionError, "exceeds 1 MiB"):
            scan_sensitive_material(str(self.snapshot), str(instance))


if __name__ == "__main__":
    unittest.main()
