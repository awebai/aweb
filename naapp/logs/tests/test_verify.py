from __future__ import annotations

import pytest

from aweb_logs.verify import verify_chain

from .chain_cases import ChainCase, cases


@pytest.mark.parametrize("case", cases(), ids=lambda case: case.name)
def test_verify_reports_what_the_chain_shows(case: ChainCase) -> None:
    report = verify_chain(
        case.genesis,
        case.events,
        receipt_keys=frozenset(case.receipt_keys),
        checkpoint_keys=frozenset(case.checkpoint_keys),
        receipts=case.receipts,
        checkpoints=case.checkpoints,
    )
    assert report.to_json() == case.report
