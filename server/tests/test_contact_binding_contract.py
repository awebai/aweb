"""Saved recipient identity remains an explicit constraint with actionable refusal."""

import json
import pytest
from aweb.messaging.recipients import RecipientIdentityBinding
from aweb.messaging.refusals import ContactIdentityBindingRequired
from aweb.mcp.tools.refusals import send_refusal


@pytest.mark.parametrize("did", ["did:aw:recipient", "did:key:recipient"])
def test_saved_constraint_matches_only_the_expected_identity(did):
    binding = RecipientIdentityBinding(did=did)
    assert binding.matches(
        {"did_aw": "did:aw:recipient", "did_key": "did:key:recipient"}
    )
    assert not binding.matches(
        {"did_aw": "did:aw:replacement", "did_key": "did:key:replacement"}
    )


def test_contact_rebinding_refusal_keeps_its_reason_and_next_action():
    assert json.loads(send_refusal(ContactIdentityBindingRequired())) == {
        "error": "This address now belongs to a different identity. Check the contact and explicitly bind it again before sending.",
        "reason": "contact_identity_binding_required",
    }
