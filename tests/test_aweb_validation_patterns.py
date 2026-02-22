"""Tests for input validation regex patterns (slugs, aliases, contact addresses)."""

import pytest

from aweb.auth import AGENT_ALIAS_PATTERN, PROJECT_SLUG_PATTERN
from aweb.contacts_service import CONTACT_ADDRESS_PATTERN


class TestProjectSlugPattern:
    """PROJECT_SLUG_PATTERN must allow alphanumeric, slashes, underscores, dots, hyphens."""

    @pytest.mark.parametrize(
        "slug",
        [
            "my-project",
            "org/repo",
            "a",
            "my_project.v2",
            "Org/Sub/Repo",
            "123",
            "a-b_c.d/e",
        ],
    )
    def test_valid_slugs(self, slug):
        assert PROJECT_SLUG_PATTERN.match(slug), f"{slug!r} should be valid"

    @pytest.mark.parametrize(
        "slug",
        [
            "has\\backslash",
            "has space",
            "",
            "has@at",
            "has#hash",
        ],
    )
    def test_invalid_slugs(self, slug):
        assert not PROJECT_SLUG_PATTERN.match(slug), f"{slug!r} should be rejected"


class TestAgentAliasPattern:
    """AGENT_ALIAS_PATTERN must allow alphanumeric start, then alphanumeric/underscore/hyphen."""

    @pytest.mark.parametrize(
        "alias",
        [
            "alice",
            "agent1",
            "my-agent",
            "my_agent",
            "A",
            "a1-b2_c3",
        ],
    )
    def test_valid_aliases(self, alias):
        assert AGENT_ALIAS_PATTERN.match(alias), f"{alias!r} should be valid"

    @pytest.mark.parametrize(
        "alias",
        [
            "has\\backslash",
            "_starts_underscore",
            "-starts-hyphen",
            "has space",
            "",
            "has/slash",
            "has@at",
        ],
    )
    def test_invalid_aliases(self, alias):
        assert not AGENT_ALIAS_PATTERN.match(alias), f"{alias!r} should be rejected"


class TestContactAddressPattern:
    """CONTACT_ADDRESS_PATTERN must allow alphanumeric, slashes, underscores, dots, hyphens."""

    @pytest.mark.parametrize(
        "addr",
        [
            "alice",
            "org/agent",
            "my_contact.v2",
            "a-b",
            "a/b/c",
        ],
    )
    def test_valid_addresses(self, addr):
        assert CONTACT_ADDRESS_PATTERN.match(addr), f"{addr!r} should be valid"

    @pytest.mark.parametrize(
        "addr",
        [
            "has\\backslash",
            "has space",
            "",
            "has@at",
        ],
    )
    def test_invalid_addresses(self, addr):
        assert not CONTACT_ADDRESS_PATTERN.match(addr), f"{addr!r} should be rejected"
