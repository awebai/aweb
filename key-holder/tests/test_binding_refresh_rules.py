"""A holder refresh re-signs its immutable active enrollment, without creation."""

import pytest
from approval_service.verify import Trust
from aweb_key_holder.auth import Caller
from aweb_key_holder.binding_refresh import check_active_enrollment
from aweb_key_holder.keys import Refused
from aweb_key_holder.refusals import Refusal


def test_binding_refresh_does_not_replace_person_keys_or_retired_enrollment():
    key = "did:key:person"
    caller = Caller(identity="did:aw:person", key=key, timestamp="1", body=b"{}")
    trust = Trust(
        person="did:aw:person",
        organisation="example.test",
        identity_key=key,
        certificate="sha256:cert",
        issuer="did:key:issuer",
        issuer_public_key=b"",
        observed_at=1,
    )
    row = {"person": trust.person, "identity_key": key, "active": 1, "retired_at": None}
    check_active_enrollment(row, caller=caller, trust=trust)
    for changed in [
        {**row, "active": 0},
        {**row, "retired_at": 1},
    ]:
        with pytest.raises(Refused) as refused:
            check_active_enrollment(changed, caller=caller, trust=trust)
        assert refused.value.code == Refusal.BINDING_REFRESH_ENROLLMENT_CHANGED


def test_rotated_identity_key_has_enrollment_recovery_advice_not_wrong_caller():
    from dataclasses import replace

    from aweb_key_holder.binding_refresh import REFRESH_ADVICE

    caller = Caller(
        identity="did:aw:person", key="did:key:new", timestamp="1", body=b"{}"
    )
    trust = Trust(
        person=caller.identity,
        organisation="example.test",
        identity_key=caller.key,
        certificate="sha256:cert",
        issuer="did:key:issuer",
        issuer_public_key=b"",
        observed_at=1,
    )
    row = {
        "person": trust.person,
        "identity_key": "did:key:old",
        "active": 1,
        "retired_at": None,
    }
    with pytest.raises(Refused) as refused:
        check_active_enrollment(row, caller=caller, trust=trust)
    assert refused.value.code == "binding_refresh_identity_key_changed"
    assert "enrolment or recovery" in REFRESH_ADVICE[refused.value.code]
    assert "operator" in REFRESH_ADVICE[refused.value.code]
    with pytest.raises(Refused) as refused:
        check_active_enrollment(
            row, caller=replace(caller, identity="did:aw:other"), trust=trust
        )
    assert refused.value.code is Refusal.BINDING_REFRESH_PERSON_REQUIRED
