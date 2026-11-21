"""A requester's original evidence deadline is enforced, never renewed."""

import time

import pytest
from fastapi import HTTPException

from aweb_naapp.console.handoff_requester import RequesterEvidence


def test_evidence_past_its_original_deadline_refuses():
    expired = RequesterEvidence("did:aw:holder", time.monotonic_ns() - 1)
    with pytest.raises(HTTPException) as refused:
        expired.require_fresh()
    assert (refused.value.status_code, refused.value.detail) == (503, "principal_status_unavailable")


def test_evidence_within_its_window_passes():
    RequesterEvidence("did:aw:holder", time.monotonic_ns() + 60_000_000_000).require_fresh()
