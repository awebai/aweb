import tempfile
import unittest
from pathlib import Path

from vm_gate import admission
from vm_gate.errors import Refused

SHA = "a" * 40
REF = "refs/heads/measurement"
DOCKERFILE = """FROM python:3.12-bookworm
ARG GO_VERSION=1.26.11
RUN echo node_22.x
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /uvx /opt/uv/
"""


class AdmissionTests(unittest.TestCase):
    def test_exact_advertised_ref_and_sha_are_accepted(self):
        admission.validate_bundle_heads(f"{SHA} {REF}\n", SHA, REF)

    def test_wrong_customer_ref_refuses_before_allocation(self):
        with self.assertRaisesRegex(Refused, "advertised ref"):
            admission.validate_bundle_heads(
                f"{SHA} refs/heads/other-customer\n", SHA, REF
            )

    def test_matching_ref_with_other_sha_refuses(self):
        with self.assertRaisesRegex(Refused, "SHA"):
            admission.validate_bundle_heads(f"{'b' * 40} {REF}\n", SHA, REF)

    def test_required_pins_come_from_the_selected_source(self):
        self.assertEqual(
            admission.aweb_requirements(
                "module example\ngo 1.26.11\n", DOCKERFILE, SHA
            ),
            {"go": "1.26.11", "uv": "0.11.32", "node": "22", "python": "3.12"},
        )

    def test_disagreeing_source_go_pins_refuse(self):
        with self.assertRaisesRegex(Refused, "Go source pins disagree"):
            admission.aweb_requirements("go 1.26.10\n", DOCKERFILE, SHA)

    def test_ambiguous_uv_source_refuses(self):
        other = DOCKERFILE + "COPY --from=ghcr.io/astral-sh/uv:0.12.0 /uv /different\n"
        with self.assertRaisesRegex(Refused, "uv"):
            admission.aweb_requirements("go 1.26.11\n", other, SHA)

    def test_pin_mismatch_names_tool_values_sha_and_snapshot_command(self):
        with self.assertRaises(Refused) as got:
            admission.validate_snapshot({"go": "1.26.12"}, {"go": "1.26.11"}, SHA)
        message = str(got.exception)
        for expected in [
            "go",
            "1.26.12",
            "1.26.11",
            SHA,
            f"vm-gate snapshot --sha {SHA}",
        ]:
            self.assertIn(expected, message)

    def test_matching_snapshot_is_reusable_by_another_sha(self):
        admission.validate_snapshot(
            {"go": "1.26.11", "node": "22"}, {"go": "1.26.11", "node": "22"}, SHA
        )

    def test_uid_zero_is_refused_at_remote_admission(self):
        with self.assertRaisesRegex(Refused, "UID 0"):
            admission.validate_remote_uid(0)

    def test_another_nonroot_uid_is_not_uid_1000(self):
        with self.assertRaisesRegex(Refused, "1000"):
            admission.validate_remote_uid(1001)

    def test_uid_1000_is_accepted(self):
        admission.validate_remote_uid(1000)

    def test_shell_syntax_is_checked_without_executing_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "must-not-exist"
            admission.validate_command(f"touch {marker}")
            self.assertFalse(marker.exists())
            with self.assertRaisesRegex(Refused, "syntax"):
                admission.validate_command("if then")
            self.assertFalse(marker.exists())

    def test_empty_command_refuses(self):
        with self.assertRaisesRegex(Refused, "empty"):
            admission.validate_command("  ")


if __name__ == "__main__":
    unittest.main()
