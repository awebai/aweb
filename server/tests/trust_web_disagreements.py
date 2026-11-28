"""The trust-web cases the code decides differently from the model, run as
ordinary comparisons outside the gate.

Each case in trust_web_cases.DISAGREEMENTS runs here with the same signed
routes, the same readings and the same comparator as in the gate. A case that
still disagrees fails, and the run exits nonzero; the report gives, per case,
the expected and the observed decision and every mismatch. The gate does not
collect this module (it is not named test_*.py); run it with
``make test-trust-web-disagreements``.
"""

from __future__ import annotations

import pytest

from trust_web_cases import CORPUS, DISAGREEMENTS, compare, load_corpus, run_case
from trust_web_cases import stack_factory as stack_factory

__all__ = ["stack_factory"]

CASES = {case.id: case for case in load_corpus(CORPUS)}
CASE_IDS = sorted(DISAGREEMENTS)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", CASE_IDS)
async def test_disagreement(stack_factory, case_id):
    case = CASES[case_id]
    async with stack_factory() as stack:
        run = await run_case(stack, case)
    mismatches = compare(case, run)
    expected = case.result if case.premise is None else f"refused ({case.premise})"
    observed = (
        "allowed" if run.refusal is None else f"refused with {run.refusal.describe()}"
    )
    report = [
        f"{case_id} (filed as {DISAGREEMENTS[case_id]})",
        f"  expected: {expected}",
        f"  observed: {observed}",
        *(f"  {mismatch}" for mismatch in mismatches),
    ]
    print("\n".join(report))
    assert mismatches == [], "\n".join(report)
