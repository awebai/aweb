"""Public mode normalization shared by embedding hosts and OSS adapters."""
import pytest

from aweb.inbound_modes import normalize_inbound_mode


@pytest.mark.parametrize("value,want", [(None, "open"), ("", "open"), ("  ", "open"), (" OPEN ", "open"), ("team_and_contacts", "team_and_contacts"), (" contacts_only ", "contacts_only")])
def test_normalize_inbound_mode(value, want):
    assert normalize_inbound_mode(value) == want


def test_caller_owns_default():
    assert normalize_inbound_mode(None, default="team_and_contacts") == "team_and_contacts"
    assert normalize_inbound_mode("", default="contacts_only") == "contacts_only"


@pytest.mark.parametrize("value", ["contacts-only", "contacts_or_teammates", "team", "bogus"])
def test_normalize_inbound_mode_rejects_unknown_wire_value(value):
    with pytest.raises(ValueError, match="inbound_mode must be one of"):
        normalize_inbound_mode(value)


def test_default_must_be_canonical():
    with pytest.raises(ValueError):
        normalize_inbound_mode(None, default="unknown")
