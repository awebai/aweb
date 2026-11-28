"""The identity-log vectors the federation authority-state vector was ACKed against.

scripts/check_vector_provenance.py pins the exact bytes of the federation
pre-activation vectors. federation-authority-state-v1.json in turn records
the bytes and digest of each identity-log vector it relies on; those files
must still be the ones it records, and none may be copied into it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "docs" / "vectors"
_REFERENCED = {
    "docs/vectors/identity-log-v1.json",
    "docs/vectors/identity-log-negative-v1.json",
    "docs/vectors/identity-log-raw-wire-v1.json",
}


def test_authority_state_references_the_identity_log_vectors_unchanged() -> None:
    state = json.loads(
        (_VECTORS / "federation-authority-state-v1.json").read_text(encoding="utf-8")
    )
    references = state["identity_log_references"]
    assert sorted(reference["path"] for reference in references) == sorted(_REFERENCED)
    for reference in references:
        assert reference["embedded"] is False
        body = (_ROOT / reference["path"]).read_bytes()
        assert (reference["bytes"], reference["sha256"]) == (
            len(body),
            hashlib.sha256(body).hexdigest(),
        )
