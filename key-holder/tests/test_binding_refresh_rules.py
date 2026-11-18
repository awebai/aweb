"""A holder refresh re-signs its immutable active enrollment, without creation."""

import pytest
from approval_service.verify import Trust
from aweb_key_holder.auth import Caller
from aweb_key_holder.binding_refresh import RefreshFailure, check_active_enrollment
from aweb_key_holder.keys import Refused


def test_binding_refresh_does_not_replace_person_keys_or_retired_enrollment():
    key = "did:key:person"
    caller = Caller("did:aw:person", key, "1", b"{}")
    trust = Trust(
        "did:aw:person", "example.test", key, "sha256:cert", "did:key:issuer", b"", 1
    )
    row = {"person": trust.person, "identity_key": key, "active": 1, "retired_at": None}
    check_active_enrollment(row, caller=caller, trust=trust)
    for changed in [
        {**row, "active": 0},
        {**row, "retired_at": 1},
        {**row, "identity_key": "another key"},
    ]:
        with pytest.raises(Refused) as refused:
            check_active_enrollment(changed, caller=caller, trust=trust)
        assert refused.value.code == RefreshFailure.ENROLLMENT_CHANGED
