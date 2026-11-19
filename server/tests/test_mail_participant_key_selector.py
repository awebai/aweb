"""A retained read-attribution key alone does not select a stable send recipient."""

import pytest
from aweb.messaging.mail_routing import explicit_mail_target_matches_participant


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "stable", "matches"),
    [
        ("did:key:recorded-recipient", None, False),
        ("did:key:another-recipient", None, False),
        ("did:key:recorded-recipient", "did:aw:recipient", True),
        ("did:aw:recipient", None, True),
    ],
)
async def test_send_selector_needs_the_recorded_identity_not_only_its_retained_key(
    key, stable, matches
):
    class NoMembershipLookup:
        def get_manager(self, _name):
            raise AssertionError("Explicit stored-party selection does not choose a new member")

    participant = {
        "did": "did:aw:recipient",
        "current_did_key": "did:key:recorded-recipient",
        "alias": "recipient",
    }
    assert (
        await explicit_mail_target_matches_participant(
            NoMembershipLookup(), participant, to_did=key, to_stable_id=stable
        )
        is matches
    )
