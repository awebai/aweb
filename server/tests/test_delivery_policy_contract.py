"""Policy refusals retain actionable text through the federation adapter."""

from aweb.federation.errors import FederationPolicyRefused, authority_error_body
from aweb.messaging.delivery_policy import DeliveryPolicyRefused, DeliverySender
from aweb.messaging.refusals import DeliveryRefusalCode


def test_federation_policy_refusal_keeps_reason_and_actionable_detail():
    detail = "Recipient only accepts messages from exact active contacts. Ask the recipient to add your exact address as a contact or check their inbound policy."
    native = DeliveryPolicyRefused(
        code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED, detail=detail
    )
    carried = FederationPolicyRefused(native)
    body = authority_error_body(carried, correlation_id="correlation")
    assert body == {
        "reason": "recipient_policy_rejected",
        "detail": detail,
        "retryable": False,
        "correlation_id": "correlation",
    }
    assert native.status_code == carried.http_status == 403
    assert body["detail"].endswith(
        "Ask the recipient to add your exact address as a contact or check their inbound policy."
    )


def test_contact_identity_uses_verified_stable_did_and_keeps_current_key_for_membership():
    sender = DeliverySender(
        did="did:key:signer",
        address="example.test/sender",
        verified_dids=("did:aw:sender", "did:key:signer"),
    )
    assert sender.contact_did() == "did:aw:sender"
    assert sender.identity_dids() == ["did:aw:sender", "did:key:signer"]
