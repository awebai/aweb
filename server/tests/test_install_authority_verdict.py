"""Install authority's rules, apart from the reads and the policy call.

``install_subject_rule`` decides whom the policy is asked about, asking for
the internal-auth context only once a certificate caller passes;
``policy_verdict`` decides what the policy's answer means. Every branch of
each is a row here. The database tests of install authority keep what only
they prove: the policy is read inside the mutation's transaction, and a
forwarded actor's membership is read there.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from aweb.auth_context import GrantContext
from aweb.install_admins import InstallAdminGrantError
from aweb.install_authority import (
    CertificateInstallAdminSubject,
    INTERNAL,
    InternalInstallAdminSubject,
    install_subject_rule,
    policy_verdict,
)
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL
from aweb.team_auth_deps import TeamIdentity

TEAM = "ops:example.com"
ACTOR = "6c1d3c4e-0d0b-4c55-9a3b-7a3e2b9f0c11"
PRINCIPAL = "2f0e4d8a-1c6b-4f4e-8d7a-5b9c3e1a2d44"


def caller(**changes) -> TeamIdentity:
    return replace(
        TeamIdentity(
            team_id=TEAM,
            alias="alice",
            did_key="did:key:alice",
            did_aw="did:aw:alice",
            address="example.com/alice",
            agent_id=ACTOR,
            identity_scope="global",
            certificate_id="cert-1",
        ),
        **changes,
    )


def internal(**changes) -> dict:
    return {
        "team_id": TEAM,
        "principal_type": "u",
        "principal_id": PRINCIPAL,
        "actor_id": ACTOR,
        **changes,
    }


GRANT = GrantContext(
    grant_id="b1d2c3e4-0000-4000-8000-000000000001",
    session_did_key="did:key:session",
    issuing_certificate_id="cert-1",
    scopes=("coord.write",),
    expires_at=datetime.now(UTC) + timedelta(hours=1),
)

CERTIFICATE_SUBJECT = CertificateInstallAdminSubject(
    team_id=TEAM, agent_id=ACTOR, certificate_id="cert-1", did_key="did:key:alice"
)


def internal_subject(principal_type: str = "u") -> InternalInstallAdminSubject:
    return InternalInstallAdminSubject(
        team_id=TEAM,
        principal_type=principal_type,
        principal_id=PRINCIPAL,
        actor_id=ACTOR,
    )


NOT_FOUND = (404, RESOURCE_NOT_FOUND_DETAIL)
ADMIN_REQUIRED = (
    403,
    {
        "code": "admin_required",
        "message": "Ask a team administrator to approve this installation action",
    },
)
UNAUTHENTICATED = (401, "Authentication required")


def decide(identity, forwarded):
    """Run the subject rule; return its verdict and the facts it asked for."""
    rule = install_subject_rule(TEAM, identity)
    asked = []
    try:
        ask = next(rule)
        while True:
            asked.append(ask)
            ask = rule.send(forwarded)
    except StopIteration as done:
        return done.value, asked


SUBJECT_ROWS = [
    ("a certificate caller in the team", caller(), None, CERTIFICATE_SUBJECT),
    (
        "a certificate caller from another team",
        caller(team_id="other:example.com"),
        None,
        NOT_FOUND,
    ),
    (
        "a certificate caller acting under a grant",
        caller(grant=GRANT),
        None,
        ADMIN_REQUIRED,
    ),
    (
        "a grant is refused before a forwarded caller is considered",
        caller(grant=GRANT),
        internal(),
        ADMIN_REQUIRED,
    ),
    ("a forwarded user", None, internal(), internal_subject("u")),
    (
        "a forwarded API key",
        None,
        internal(principal_type="k"),
        internal_subject("k"),
    ),
    (
        "a forwarded caller for another team",
        None,
        internal(team_id="other:example.com"),
        NOT_FOUND,
    ),
    (
        "a forwarded caller is the subject beside a certificate caller",
        caller(),
        internal(),
        internal_subject("u"),
    ),
    ("no caller", None, None, UNAUTHENTICATED),
]


@pytest.mark.parametrize(
    ("identity", "forwarded", "expected"),
    [row[1:] for row in SUBJECT_ROWS],
    ids=[row[0] for row in SUBJECT_ROWS],
)
def test_install_subject_rule(identity, forwarded, expected):
    verdict, _ = decide(identity, forwarded)
    if isinstance(expected, tuple):
        assert isinstance(verdict, HTTPException)
        assert (verdict.status_code, verdict.detail) == expected
    else:
        assert verdict == expected


@pytest.mark.parametrize(
    ("identity", "forwarded", "asked"),
    [
        (caller(team_id="other:example.com"), internal(), []),
        (caller(grant=GRANT), internal(), []),
        (caller(), None, [INTERNAL]),
        (None, internal(), [INTERNAL]),
        (None, None, [INTERNAL]),
    ],
    ids=[
        "another team asks for no internal context",
        "a grant asks for no internal context",
        "a certificate caller in the team asks once",
        "a forwarded caller asks once",
        "no caller asks once",
    ],
)
def test_a_refused_certificate_caller_reads_no_internal_context(
    identity, forwarded, asked
):
    assert decide(identity, forwarded)[1] == asked


UNAVAILABLE_GRANTS = InstallAdminGrantError(
    "authority_unavailable", "Installation administration is unavailable", 503
)
POLICY_UNAVAILABLE = (
    503,
    {
        "code": "install_policy_unavailable",
        "message": "Installation policy is unavailable",
    },
)

POLICY_ROWS = [
    ("the policy permits", {"returned": True}, None),
    ("the policy declines", {"returned": False}, ADMIN_REQUIRED),
    ("the policy answers nothing", {"returned": None}, ADMIN_REQUIRED),
    ("a truthy answer is not a permit", {"returned": 1}, ADMIN_REQUIRED),
    (
        "a returned service error is not a permit",
        {"returned": UNAVAILABLE_GRANTS},
        ADMIN_REQUIRED,
    ),
    ("the policy fails", {"raised": RuntimeError("down")}, POLICY_UNAVAILABLE),
]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [row[1:] for row in POLICY_ROWS],
    ids=[row[0] for row in POLICY_ROWS],
)
def test_policy_verdict(answer, expected):
    verdict = policy_verdict(**answer)
    if expected is None:
        assert verdict is None
    else:
        assert isinstance(verdict, HTTPException)
        assert (verdict.status_code, verdict.detail) == expected


def test_a_raised_service_error_is_the_answer_as_it_is():
    assert policy_verdict(raised=UNAVAILABLE_GRANTS) is UNAVAILABLE_GRANTS
