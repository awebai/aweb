"""One-use links: a high-entropy token handed out once, only its verifier at rest."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from aweb_naapp.runtime.links import LinkLifetime, link_verifier, new_link_token

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def test_a_new_token_is_high_entropy_and_paired_with_its_verifier():
    tokens = {new_link_token() for _ in range(64)}
    assert len(tokens) == 64
    for token, verifier in tokens:
        assert len(token) >= 43
        assert verifier == hashlib.sha256(token.encode()).hexdigest() == link_verifier(token)
        assert token not in verifier


def test_a_link_is_usable_until_it_expires_is_revoked_or_is_used():
    fresh = LinkLifetime(expires_at=NOW + timedelta(minutes=5), revoked_at=None, used_at=None)
    assert fresh.usable_at(NOW)
    assert not fresh.usable_at(NOW + timedelta(minutes=5))
    revoked = LinkLifetime(expires_at=fresh.expires_at, revoked_at=NOW, used_at=None)
    assert not revoked.usable_at(NOW)
    used = LinkLifetime(expires_at=fresh.expires_at, revoked_at=None, used_at=NOW)
    assert not used.usable_at(NOW)
