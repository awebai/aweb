"""Admission of the released-kernel wake receipt alongside ordinary user paths."""

from enum import Enum


class KernelWakeOutcome(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"


def add_kernel_wake_result(*, qualification, kernel_receipt):
    """Enforce docs/wake-runner-integrity.md:30-33: no kernel receipt, no pass."""
    receipt = (
        kernel_receipt
        if isinstance(kernel_receipt, dict)
        and kernel_receipt.get("result")
        in (KernelWakeOutcome.PASSED.value, KernelWakeOutcome.FAILED.value)
        else {
            "result": KernelWakeOutcome.FAILED.value,
            "error": (
                "released OATS kernel wake evidence is missing or malformed. "
                "Re-run the user-paths stage with the prepared candidate runtime, "
                "inspect released-kernel-wake.json, then retry qualification."
            ),
        }
    )
    result = {**qualification, "released_kernel_wake": receipt}
    if receipt.get("result") != KernelWakeOutcome.PASSED.value:
        result["status"] = KernelWakeOutcome.FAILED.value
    return result
