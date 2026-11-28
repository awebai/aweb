"""The Phase A checkpoint and cohort rule, apart from the rows it is read from.

``phase_a_verdict`` decides from the stored checkpoint and the address's
stored cohort. Every checkpoint case of the federation authority state vector
is a row here except the concurrent forks, which only PostgreSQL can order;
the other rows cover the branches the vector does not name. The database
tests of the repository keep what only they prove: the locks, the CAS update,
the fences, the cohort writes and the database clock.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from awid.federation_errors import FederationAuthorityError

from aweb.federation.authority_state import (
    ExistingCohort,
    PhaseAPlan,
    phase_a_verdict,
)
from test_federation_authority_core import (
    _STATE_VECTOR,
    first_checkpoint,
    vector_checkpoint_candidate,
    vector_cohort,
    vector_snapshot,
)

RACES = {"two_n_plus_one_forks_allow_one_winner"}
CASES = [
    case for case in _STATE_VECTOR["checkpoint_cases"] if case["name"] not in RACES
]


def outcome(verdict):
    """A comparable form of a plan or a refusal."""
    if isinstance(verdict, FederationAuthorityError):
        return (verdict.reason, verdict.did_aw, verdict.observed_sequence)
    return verdict


def refusal(reason, candidate=None):
    if candidate is None:
        return (reason, None, None)
    return (reason, candidate.did_aw, candidate.seq)


def written(checkpoint: str, revision: int, *, invalidate_peers=False) -> PhaseAPlan:
    """A plan that writes a first cohort for the address."""
    return PhaseAPlan(
        checkpoint=checkpoint,
        revision=revision,
        reused_generation=None,
        invalidate_peers=invalidate_peers,
        generation=1,
        cohort_revision=1,
    )


ACTIONS = {"insert": "insert", "idempotent": "keep", "advance": "advance"}


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_checkpoint_vector_cases(case):
    candidate = vector_checkpoint_candidate(case)
    expected = case["expected"]
    current = vector_snapshot(case["snapshot"]) if case["snapshot"] else None

    verdict = phase_a_verdict(
        candidate, vector_cohort(candidate, expected["revision"]), current, None
    )

    if expected["action"] == "reject":
        assert outcome(verdict) == refusal(expected["reason"], candidate)
    else:
        advance = expected["action"] == "advance"
        assert verdict == written(
            ACTIONS[expected["action"]], expected["revision"], invalidate_peers=advance
        )
        assert expected.get("invalidate_all_older_did_cohorts", advance) is advance


def test_every_checkpoint_case_is_a_row_or_a_race():
    names = {case["name"] for case in _STATE_VECTOR["checkpoint_cases"]}
    assert names == {case["name"] for case in CASES} | RACES


CANDIDATE = first_checkpoint()
STORED = vector_snapshot(
    {
        "seq": CANDIDATE.seq,
        "entry_hash": CANDIDATE.entry_hash,
        "state_hash": CANDIDATE.state_hash,
        "current_did_key": CANDIDATE.current_did_key,
        "revision": 1,
    }
)
LATER = replace(
    CANDIDATE,
    seq=CANDIDATE.seq + 1,
    entry_hash="c" * 64,
    contains_snapshot=True,
    expected_revision=1,
    expected_entry_hash=CANDIDATE.entry_hash,
)


def cohort(candidate, revision):
    return vector_cohort(candidate, revision)


def stored_cohort(*, matches=True, live=True):
    return ExistingCohort(matches=matches, live=live, generation=4, revision=7)


ROWS = [
    (
        "a first observation that expects a stored revision",
        replace(CANDIDATE, expected_revision=1),
        1,
        None,
        None,
        refusal("federation_authority_cas_conflict"),
    ),
    (
        "the same sequence with another entry hash",
        replace(CANDIDATE, entry_hash="e" * 64),
        1,
        STORED,
        None,
        refusal("sender_did_log_split_view", replace(CANDIDATE, entry_hash="e" * 64)),
    ),
    (
        "the same entry with another state hash",
        replace(CANDIDATE, state_hash="e" * 64),
        1,
        STORED,
        None,
        refusal("sender_did_log_split_view", replace(CANDIDATE, state_hash="e" * 64)),
    ),
    (
        "the same entry with another current key",
        replace(CANDIDATE, current_did_key="did:key:z6Mkother"),
        1,
        STORED,
        None,
        refusal(
            "sender_did_log_split_view",
            replace(CANDIDATE, current_did_key="did:key:z6Mkother"),
        ),
    ),
    (
        "a later entry expecting a stale revision",
        replace(LATER, expected_revision=2),
        2,
        STORED,
        None,
        refusal("federation_authority_cas_conflict"),
    ),
    (
        "a later entry expecting another entry hash",
        replace(LATER, expected_entry_hash="f" * 64),
        2,
        STORED,
        None,
        refusal("federation_authority_cas_conflict"),
    ),
    (
        "a cohort naming another checkpoint revision",
        CANDIDATE,
        2,
        None,
        None,
        refusal("federation_authority_cas_conflict"),
    ),
    (
        "a cohort naming the stored revision for an advance",
        LATER,
        1,
        STORED,
        None,
        refusal("federation_authority_cas_conflict"),
    ),
    (
        "the live cohort is already the exact tuple",
        CANDIDATE,
        1,
        STORED,
        stored_cohort(),
        PhaseAPlan("keep", 1, 4, False, 5, 8),
    ),
    (
        "an expired cohort with the exact tuple is written again",
        CANDIDATE,
        1,
        STORED,
        stored_cohort(live=False),
        PhaseAPlan("keep", 1, None, False, 5, 8),
    ),
    (
        "a changed source replaces the cohort and invalidates the DID's others",
        CANDIDATE,
        1,
        STORED,
        stored_cohort(matches=False),
        PhaseAPlan("keep", 1, None, True, 5, 8),
    ),
    (
        "an advance under a live exact cohort reuses it",
        LATER,
        2,
        STORED,
        stored_cohort(),
        PhaseAPlan("advance", 2, 4, True, 5, 8),
    ),
]


@pytest.mark.parametrize(
    ("candidate", "revision", "current", "existing", "expected"),
    [row[1:] for row in ROWS],
    ids=[row[0] for row in ROWS],
)
def test_phase_a_verdict(candidate, revision, current, existing, expected):
    verdict = phase_a_verdict(candidate, cohort(candidate, revision), current, existing)
    assert outcome(verdict) == expected
