"""Grant revocation and calendar lifetime have one transport-independent rule."""

from datetime import UTC, datetime, timedelta

import pytest
from aweb.grant_expiry import GrantLifetimeState, grant_lifetime_state


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_finite_grant_ends_at_its_exact_deadline(offset):
    issued = datetime(2024, 2, 29, 12, tzinfo=UTC)
    deadline = issued + timedelta(hours=1)
    state = grant_lifetime_state(
        issued_at=issued,
        expires_at=deadline,
        revoked_at=None,
        now=deadline + timedelta(microseconds=offset),
    )
    expected = GrantLifetimeState.ACTIVE if offset < 0 else GrantLifetimeState.EXPIRED
    assert state is expected


@pytest.mark.parametrize(
    "expiry", [datetime(2024, 3, 1, tzinfo=UTC), datetime(2124, 2, 29, tzinfo=UTC)]
)
def test_revocation_ends_both_finite_and_never_grants(expiry):
    issued = datetime(2024, 2, 29, tzinfo=UTC)
    now = datetime(2224, 3, 1, tzinfo=UTC)
    assert (
        grant_lifetime_state(issued_at=issued, expires_at=expiry, revoked_at=now, now=now)
        is GrantLifetimeState.REVOKED
    )


@pytest.mark.parametrize("offset", [-1, 0])
def test_never_grant_uses_calendar_years_from_a_leap_day(offset):
    # docs/identity.md:755-763 reserves at least 99 calendar years for never;
    # February 29 maps to February 28 when that year has no leap day.
    issued = datetime(2024, 2, 29, 12, tzinfo=UTC)
    threshold = datetime(2123, 2, 28, 12, tzinfo=UTC)
    state = grant_lifetime_state(
        issued_at=issued,
        expires_at=threshold + timedelta(microseconds=offset),
        revoked_at=None,
        now=datetime(2224, 3, 1, tzinfo=UTC),
    )
    expected = GrantLifetimeState.ACTIVE if offset == 0 else GrantLifetimeState.EXPIRED
    assert state is expected


def test_missing_issuance_evidence_cannot_make_a_deadline_never_expire():
    deadline = datetime(2124, 2, 29, tzinfo=UTC)
    assert (
        grant_lifetime_state(
            issued_at=None,
            expires_at=deadline,
            revoked_at=None,
            now=deadline,
        )
        is GrantLifetimeState.EXPIRED
    )
