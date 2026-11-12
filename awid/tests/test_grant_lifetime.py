"""Grant mechanism policy; the default remains revoke-only pending approval."""
from datetime import datetime, timedelta, timezone

import pytest

from awid.grant_lifetime import default_grant_ttl_seconds, grant_deadline


def test_default_remains_never_while_the_policy_flip_is_held(monkeypatch):
    monkeypatch.delenv("AWEB_GRANT_DEFAULT_TTL_SECONDS", raising=False)
    assert default_grant_ttl_seconds() is None


def test_one_setting_can_select_a_bounded_default(monkeypatch):
    monkeypatch.setenv("AWEB_GRANT_DEFAULT_TTL_SECONDS", "86400")
    assert default_grant_ttl_seconds() == 86400


@pytest.mark.parametrize("value", ["0", "59", "2592001", "-1", "nonsense"])
def test_invalid_default_is_refused(monkeypatch, value):
    monkeypatch.setenv("AWEB_GRANT_DEFAULT_TTL_SECONDS", value)
    with pytest.raises(ValueError):
        default_grant_ttl_seconds()


def test_finite_deadline_is_absolute_and_legacy_never_stays_unbounded():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    assert grant_deadline(now, 86400) == now + timedelta(days=1)
    assert grant_deadline(now, None) is None
