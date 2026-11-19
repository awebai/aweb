"""A recorded participant key identifies that same thread party, not a new actor."""

import pytest

from aweb.messaging.mail_routing import explicit_mail_target_matches_participant


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "matches"),
    [("did:key:recorded-recipient", True), ("did:key:another-recipient", False)],
)
async def test_explicit_mail_did_identifies_the_recorded_participant_key(key, matches):
    class NoMembershipLookup:
        def get_manager(self, _name):
            raise AssertionError("A recorded participant reference needs no roster lookup")

    participant = {
        "did": "did:aw:recipient",
        "current_did_key": "did:key:recorded-recipient",
        "alias": "recipient",
    }
    assert await explicit_mail_target_matches_participant(
        NoMembershipLookup(), participant, to_did=key
    ) is matches
