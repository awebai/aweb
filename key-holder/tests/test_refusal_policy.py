"""The holder distinguishes caller input, stale state and internal failures."""

from http import HTTPStatus

from approval_service.verify import Refused as ApprovalRefused
from aweb_key_holder.keys import Refused


def test_unknown_library_refusal_is_an_internal_failure_instead_of_bad_credentials():
    from aweb_key_holder.refusals import refusal_status

    assert (
        refusal_status(ApprovalRefused("unexpected_new_library_code"))
        == HTTPStatus.INTERNAL_SERVER_ERROR
    )


def test_holder_failures_have_named_semantics_and_never_default_to_unauthorized():
    from aweb_key_holder.refusals import Refusal, refusal_status

    assert (
        refusal_status(Refused(Refusal.STORAGE_UNAVAILABLE))
        == HTTPStatus.SERVICE_UNAVAILABLE
    )
    assert (
        refusal_status(Refused(Refusal.IDENTITY_CHAIN_REQUIRED))
        == HTTPStatus.UNAUTHORIZED
    )
    assert refusal_status(Refused(Refusal.REQUESTER_MISMATCH)) == HTTPStatus.FORBIDDEN
    assert (
        refusal_status(Refused(Refusal.CREDENTIAL_DUPLICATE)) == HTTPStatus.BAD_REQUEST
    )
    assert refusal_status(Refused(Refusal.KEY_ALREADY_EXISTS)) == HTTPStatus.CONFLICT
    assert (
        refusal_status(ApprovalRefused("approval_assertion_invalid"))
        == HTTPStatus.UNAUTHORIZED
    )
