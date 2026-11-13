"""Closed public policy data; a valid digest supplies no admission authority."""

import hashlib

import pytest
from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy, PolicyInvalid

SERVICE = "customer-signer"


def unsigned():
    return {
        "version": 1,
        "teams": ["engineering:example.org", "ops:example.org"],
        "root_selector": {"kind": "service_endorsed_root", "service_id": SERVICE},
        "subject_kinds": ["local_agent", "registered_agent"],
        "member_role": "member",
        "bounds": {"max_active": 12, "rate_window_seconds": 3600, "max_per_window": 20},
    }


def test_policy_digest_is_the_exact_lf_domain_and_canonical_public_fields():
    fields = unsigned()
    policy = AdmissionPolicy.from_unsigned(fields, service_id=SERVICE)
    expected = "sha256:" + hashlib.sha256(b"aweb.admission-policy/1\n" + canonical_json_bytes(fields)).hexdigest()
    assert policy.fields() == {**fields, "digest": expected}
    assert AdmissionPolicy.from_fields(policy.fields(), service_id=SERVICE) == policy
    fields["bounds"]["max_active"] = 999
    snapshot = policy.fields()
    snapshot["teams"].append("another:example.org")
    assert policy.fields()["bounds"]["max_active"] == 12
    assert len(policy.fields()["teams"]) == 2


@pytest.mark.parametrize("changed", [
    {"version": True}, {"version": 0}, {"version": 2**53},
    {"teams": []}, {"teams": ["engineering:example.org"]*2},
    {"teams": ["ops:example.org", "engineering:example.org"]}, {"teams": ["wrong/team"]},
    {"root_selector": {"kind": "any_agent", "service_id": SERVICE}},
    {"root_selector": {"kind": "service_endorsed_root", "service_id": "other"}},
    {"root_selector": {"kind": "service_endorsed_root", "service_id": SERVICE, "root": "implicit"}},
    {"subject_kinds": []}, {"subject_kinds": ["human"]},
    {"subject_kinds": ["registered_agent", "local_agent"]},
    {"member_role": "admin"}, {"bootstrap": True},
    {"bounds": {"max_active": 12, "rate_window_seconds": 0, "max_per_window": 20}},
    {"bounds": {"max_active": True, "rate_window_seconds": 3600, "max_per_window": 20}},
    {"bounds": {"max_active": 12, "rate_window_seconds": 3600, "max_per_window": float("inf")}},
    {"bounds": {"max_active": 12, "rate_window_seconds": 3600}},
    {"bounds": {"max_active": 12, "rate_window_seconds": 3600, "max_per_window": 20, "aggregate": 30}},
])
def test_policy_refuses_unbounded_wrong_authority_or_unknown_fields(changed):
    with pytest.raises(PolicyInvalid):
        AdmissionPolicy.from_unsigned({**unsigned(), **changed}, service_id=SERVICE)


def test_policy_reader_checks_digest_not_only_shape_and_preserves_exact_version():
    policy = AdmissionPolicy.from_unsigned(unsigned(), service_id=SERVICE)
    for changed in (
        {**policy.fields(), "digest": "sha256:"+"a"*64},
        {**policy.fields(), "version": 2},
    ):
        with pytest.raises(PolicyInvalid):
            AdmissionPolicy.from_fields(changed, service_id=SERVICE)
    # An intentional operator-created next version has a different digest;
    # no reader silently edits/re-hashes a stored policy on a miss.
    newer = AdmissionPolicy.from_unsigned({**unsigned(), "version": 2}, service_id=SERVICE)
    assert newer.digest != policy.digest
