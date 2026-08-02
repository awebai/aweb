from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import generate_federation_error_reference as generator


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "docs/vectors/federation-authority-state-v1.json"


class FederationErrorReferenceGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(VECTOR.read_text(encoding="utf-8"))

    def test_reference_contains_every_canonical_source_error_exactly_once(self) -> None:
        specs = generator.canonical_error_specs()
        rendered = generator.render_reference(self.contract)

        self.assertEqual(len(specs), 42)
        for spec in specs:
            error = {
                "reason": spec.reason,
                "http_status": spec.http_status,
            }
            row_prefix = f"| `{error['reason']}` |"
            self.assertEqual(rendered.count(row_prefix), 1, error["reason"])
            self.assertIn(f"| {error['http_status']} |", next(
                line for line in rendered.splitlines() if line.startswith(row_prefix)
            ))
        self.assertIn("`detail`, `reason`, `retryable`, and `correlation_id`", rendered)
        self.assertIn("`federation_rate_limited`", rendered)
        self.assertIn("Retry-After", rendered)

    def test_duplicate_reason_is_rejected(self) -> None:
        contract = json.loads(json.dumps(self.contract))
        contract["stable_errors"].append(dict(contract["stable_errors"][0]))

        with self.assertRaisesRegex(generator.ReferenceContractError, "duplicate stable error"):
            generator.render_reference(contract)

    def test_new_source_reason_is_rejected_until_its_support_meaning_is_classified(self) -> None:
        contract = json.loads(json.dumps(self.contract))
        new_error = {
            "reason": "new_federation_failure",
            "detail": "new_federation_failure",
            "http_status": 503,
            "retryable": True,
            "retry_after_required": False,
        }
        contract["stable_errors"].append(new_error)
        specs = (*generator.canonical_error_specs(), generator.FederationErrorSpec(
            reason="new_federation_failure",
            http_status=503,
            retryable=True,
            retry_after_required=False,
        ))

        with self.assertRaisesRegex(generator.ReferenceContractError, "unclassified stable error"):
            generator.render_reference(contract, error_specs=specs)

    def test_vector_status_drift_from_canonical_source_is_rejected(self) -> None:
        contract = json.loads(json.dumps(self.contract))
        contract["stable_errors"][0]["http_status"] = 418

        with self.assertRaisesRegex(
            generator.ReferenceContractError,
            "does not match canonical federation error source",
        ):
            generator.render_reference(contract)

    def test_retry_after_contract_is_rejected_when_inconsistent(self) -> None:
        contract = json.loads(json.dumps(self.contract))
        contract["stable_errors"][0]["retry_after_required"] = True

        with self.assertRaisesRegex(generator.ReferenceContractError, "Retry-After"):
            generator.render_reference(contract)

    def test_check_rejects_stale_output_without_rewriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "federation-error-reference.md"
            original = b"stale\n"
            output.write_bytes(original)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = generator.main(
                    ["--vector", str(VECTOR), "--output", str(output), "--check"]
                )

            self.assertEqual(status, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("federation error reference is stale", stderr.getvalue())
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
