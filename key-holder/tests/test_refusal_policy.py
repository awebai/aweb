"""The holder distinguishes caller input, stale state and internal failures."""

from http import HTTPStatus

import pytest
from approval_service.verify import Refused as ApprovalRefused

from aweb_key_holder.keys import Refused


@pytest.mark.asyncio
async def test_unknown_library_refusal_is_an_internal_failure_instead_of_bad_credentials(
    registry_client, tmp_path, caplog
):
    import json

    from aweb_key_holder.enrollment import Holder
    from aweb_key_holder.http import create_app
    from aweb_key_holder.keys import KeyStore

    holder = Holder(
        KeyStore.create(tmp_path / "private", organisation="example.test"),
        registry=registry_client,
        origin="https://holder.example",
    )
    error = ApprovalRefused("unexpected_new_library_code")
    with caplog.at_level("ERROR", logger="aweb_key_holder.http"):
        response = await create_app(holder).exception_handlers[ApprovalRefused](
            None, error
        )
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(response.body) == {
        "error": {
            "code": "unexpected_new_library_code",
            "message": "Ask the operator to inspect the holder error log, then retry.",
        }
    }
    assert "unexpected_new_library_code" in caplog.text


def test_pending_enrollment_cannot_activate_before_its_artifacts_are_saved(
    registry_client, tmp_path
):
    from approval_service.grading import EnrollmentGrading
    from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

    from aweb_key_holder.enrollment import Holder
    from aweb_key_holder.keys import KeyStore

    holder = Holder(
        KeyStore.create(tmp_path / "private", organisation="example.test"),
        registry=registry_client,
        origin="https://holder.example",
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )
    _, public_key = generate_keypair()
    key = did_from_public_key(public_key)
    person = stable_id_from_did_key(key)
    holder.bootstrap_pending(person, key)
    with holder.store.connection() as database:
        row = holder._row(database, person)
        with pytest.raises(Refused) as refused:
            holder._activation(row)
    assert refused.value.code == "creation_required"
    assert (
        refused.value.reason.advice
        == "Finish the person's existing enrollment in the approval client before retrying activation."
    )


def test_holder_failures_have_named_semantics_and_never_default_to_unauthorized():
    from aweb_key_holder.refusals import Refusal, describe_refusal

    assert (
        describe_refusal(Refused(Refusal.STORAGE_UNAVAILABLE)).status
        == HTTPStatus.SERVICE_UNAVAILABLE
    )
    assert (
        describe_refusal(Refused(Refusal.IDENTITY_CHAIN_REQUIRED)).status
        == HTTPStatus.UNAUTHORIZED
    )
    assert (
        describe_refusal(Refused(Refusal.REQUESTER_MISMATCH)).status
        == HTTPStatus.FORBIDDEN
    )
    assert (
        describe_refusal(Refused(Refusal.CREDENTIAL_DUPLICATE)).status
        == HTTPStatus.BAD_REQUEST
    )
    assert (
        describe_refusal(Refused(Refusal.KEY_ALREADY_EXISTS)).status
        == HTTPStatus.CONFLICT
    )
    assert (
        describe_refusal(ApprovalRefused("approval_assertion_invalid")).status
        == HTTPStatus.UNAUTHORIZED
    )


@pytest.mark.asyncio
async def test_signed_nonobject_json_is_input_failure_before_any_effect(
    registry_client, tmp_path
):
    import base64
    import hashlib
    from datetime import UTC, datetime

    import httpx
    from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
    from awid.signing import canonical_json_bytes, sign_message

    from aweb_key_holder.enrollment import Holder
    from aweb_key_holder.http import create_app
    from aweb_key_holder.keys import KeyStore

    holder = Holder(
        KeyStore.create(tmp_path / "private", organisation="example.test"),
        registry=registry_client,
        origin="https://holder.example",
    )
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    person = stable_id_from_did_key(key)
    body = b"[]"
    timestamp = datetime.now(UTC).isoformat()
    envelope = canonical_json_bytes(
        {
            "v": 2,
            "did_aw": person,
            "aud": holder.origin,
            "method": "POST",
            "path": "/v1/humans",
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    headers = {
        "Authorization": f"DIDKey {key} {sign_message(seed, envelope)}",
        "X-AWEB-DID-AW": person,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(envelope)
        .rstrip(b"=")
        .decode(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        refused = await client.post("/v1/humans", content=body, headers=headers)
        assert refused.status_code == 400
        assert refused.json() == {
            "error": {
                "code": "request_invalid",
                "message": "Submit the documented JSON object using the person's approval client, then retry.",
            }
        }
        unauthenticated = await client.post("/v1/humans", content=body)
        assert unauthenticated.status_code == 401
    assert holder.store.audit() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,status,message",
    [
        (
            "certificate_mismatch",
            400,
            "Ask the operator to check the requested certificate and current issuer, then start a new approval request.",
        ),
        (
            "controller_mismatch",
            403,
            "Ask the operator to reload the current holder descriptor and retry with its current controller.",
        ),
        (
            "approver_not_active",
            403,
            "Use an activated approver; ask the operator to check this person's enrollment before retrying.",
        ),
        (
            "bootstrap_closed",
            403,
            "Finish the first person's existing enrollment, or ask the operator to use the normal issuance flow for another person.",
        ),
    ],
)
async def test_person_facing_refusal_response_includes_its_exact_next_step(
    registry_client, tmp_path, code, status, message
):
    import json

    from aweb_key_holder.enrollment import Holder
    from aweb_key_holder.http import create_app
    from aweb_key_holder.keys import KeyStore
    from aweb_key_holder.refusals import Refusal

    holder = Holder(
        KeyStore.create(tmp_path / "private", organisation="example.test"),
        registry=registry_client,
        origin="https://holder.example",
    )
    response = await create_app(holder).exception_handlers[Refused](
        None, Refused(Refusal(code))
    )
    assert response.status_code == status
    assert json.loads(response.body) == {"error": {"code": code, "message": message}}
    assert holder.store.audit() == []
