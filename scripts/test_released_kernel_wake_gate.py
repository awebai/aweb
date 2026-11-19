"""A green direct channel lane cannot hide a missing or failed OATS wake seam."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths_kernel_result import add_kernel_wake_result  # noqa: E402


class ReleasedKernelAdmissionTest(unittest.TestCase):
    def test_green_direct_channel_lane_cannot_hide_missing_or_failed_kernel(self):
        for receipt in (
            None,
            [],
            {},
            {"result": "FAILED", "error": "kernel wake failed"},
        ):
            with self.subTest(receipt=receipt):
                qualified = add_kernel_wake_result(
                    qualification={"status": "PASSED"}, kernel_receipt=receipt
                )
                self.assertEqual(qualified["status"], "FAILED")
                self.assertIn("error", qualified["released_kernel_wake"])
                if receipt is None or not isinstance(receipt, dict) or not receipt:
                    self.assertIn(
                        "Re-run the user-paths stage",
                        qualified["released_kernel_wake"]["error"],
                    )
                    self.assertIn(
                        "released-kernel-wake.json",
                        qualified["released_kernel_wake"]["error"],
                    )

    def test_kernel_pass_preserves_other_lane_failure(self):
        receipt = {"result": "PASSED"}
        self.assertEqual(
            add_kernel_wake_result(
                qualification={"status": "FAILED"}, kernel_receipt=receipt
            )["status"],
            "FAILED",
        )
        self.assertEqual(
            add_kernel_wake_result(
                qualification={"status": "PASSED"}, kernel_receipt=receipt
            )["status"],
            "PASSED",
        )


if __name__ == "__main__":
    unittest.main()
