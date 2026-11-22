"""Actual team-control codecs and signatures consume the shared released bytes."""

import copy
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from awid.team_control_requests import TeamControlRequestError, TeamImportRequest
from awid.unowned_team_claim import (
    ClaimArtifactError,
    ClaimSignatureError,
    SignedUnownedTeamClaim,
    UnownedTeamClaimRequest,
    read_unowned_team_claim,
)

VECTOR_ROOT = Path(__file__).resolve().parents[2] / "docs" / "vectors"
VECTORS = json.loads((VECTOR_ROOT / "team-control-requests-v1.json").read_text())
SEED = bytes.fromhex(VECTORS["seed_hex"])
SIGNER = VECTORS["signer_did_key"]


@pytest.mark.parametrize("case", VECTORS["import_cases"], ids=lambda case: case["name"])
def test_released_import_bytes_and_signatures(case):
    request = TeamImportRequest(**case["input"])
    assert request.signing_bytes() == case["canonical_payload"].encode()
    request.verify_signature(signer_did_key=SIGNER, signature=case["signature"])
    assert request.team_id == case["input"]["team_id"]


@pytest.mark.parametrize("case", VECTORS["claim_cases"], ids=lambda case: case["name"])
def test_claim_artifact_round_trips_through_the_shared_reader(case):
    request = UnownedTeamClaimRequest(**case["input"])
    assert request.signing_bytes() == case["canonical_payload"].encode()
    artifact = request.sign(signing_key=SEED)
    assert artifact.to_dict() == case["artifact"]
    assert read_unowned_team_claim(artifact.to_json()) == artifact
    assert read_unowned_team_claim(case["artifact"]) == artifact
    artifact.verify_integrity()


@pytest.mark.parametrize(
    "change",
    [
        {"awid_team_id": "other:acme.com"},
        {"email": "other@example.com"},
        {"username": "other-owner"},
        {"timestamp": "2026-05-09T12:00:01Z"},
    ],
)
def test_each_claim_target_and_time_is_bound(change):
    artifact = read_unowned_team_claim(VECTORS["claim_cases"][0]["artifact"])
    changed = SignedUnownedTeamClaim(
        request=replace(artifact.request, **change),
        signer_did_key=artifact.signer_did_key,
        signature=artifact.signature,
    )
    with pytest.raises(ClaimSignatureError, match="retry"):
        changed.verify_integrity()


def test_claim_does_not_reuse_an_import_signature_or_reinterpret_account_values():
    request = UnownedTeamClaimRequest(**VECTORS["claim_cases"][0]["input"])
    with pytest.raises(ClaimSignatureError, match="retry"):
        request.verify_signature(
            signer_did_key=SIGNER, signature=VECTORS["import_cases"][0]["signature"]
        )
    assert (
        replace(request, email="Owner@example.com").signing_bytes()
        != request.signing_bytes()
    )
    assert replace(request, username="Owner").signing_bytes() != request.signing_bytes()


@pytest.mark.parametrize("dry_run", [None, 0, 1, "false", []])
def test_import_requires_an_actual_boolean_without_coercing_it(dry_run):
    fields = {**VECTORS["import_cases"][0]["input"], "dry_run": dry_run}
    with pytest.raises(TeamControlRequestError, match="retry"):
        TeamImportRequest(**fields)


@pytest.mark.parametrize("location", ["artifact", "request"])
def test_claim_reader_refuses_unsigned_authority_fields(location):
    value = copy.deepcopy(VECTORS["claim_cases"][0]["artifact"])
    target = value if location == "artifact" else value["request"]
    target["authorized_controller"] = True
    with pytest.raises(ClaimArtifactError, match="retry"):
        read_unowned_team_claim(value)


@pytest.mark.parametrize(
    "raw", [b"[]", b"null", b'{"request":{},"request":{}}', b"{} {}", b'"\\ud800"']
)
def test_claim_json_reader_refuses_malformed_artifacts(raw):
    with pytest.raises(ClaimArtifactError, match="retry"):
        read_unowned_team_claim(raw)


def test_claim_unicode_escape_neighbors_round_trip_without_loss():
    artifact = read_unowned_team_claim(VECTORS["claim_cases"][0]["artifact"])
    request = replace(artifact.request, email="owner+雪😀@example.com")
    signed = request.sign(signing_key=SEED)
    escaped = json.dumps(signed.to_dict(), ensure_ascii=True).encode()
    assert read_unowned_team_claim(escaped) == signed
    read_unowned_team_claim(escaped).verify_integrity()
    with pytest.raises(ClaimArtifactError) as error:
        read_unowned_team_claim(escaped.replace(b"owner+", b"\\ud800"))
    assert (
        str(error.value)
        == "email must contain valid Unicode; correct the request and retry."
    )


def test_claim_artifact_is_immutable_and_returns_detached_transport_data():
    artifact = read_unowned_team_claim(VECTORS["claim_cases"][0]["artifact"])
    transport = artifact.to_dict()
    transport["request"]["email"] = "other@example.com"
    artifact.verify_integrity()
    assert artifact.request.email == "owner@example.com"
    with pytest.raises(FrozenInstanceError):
        artifact.request.email = "other@example.com"


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (
            {"awid_team_id": ""},
            "awid_team_id is required; correct the request and retry.",
        ),
        ({"timestamp": None}, "timestamp must be text; correct the request and retry."),
        (
            {"email": "\ud800"},
            "email must contain valid Unicode; correct the request and retry.",
        ),
    ],
)
def test_claim_value_refusals_name_the_recovery(edit, message):
    with pytest.raises(ClaimArtifactError) as error:
        UnownedTeamClaimRequest(**{**VECTORS["claim_cases"][0]["input"], **edit})
    assert str(error.value) == message


def test_claim_refusals_name_the_signature_and_key_recovery():
    request = UnownedTeamClaimRequest(**VECTORS["claim_cases"][0]["input"])
    with pytest.raises(ClaimArtifactError) as error:
        request.sign(signing_key=b"wrong")
    assert str(error.value) == "Use a 32-byte Ed25519 signing seed and retry."
    with pytest.raises(ClaimSignatureError) as error:
        request.verify_signature(signer_did_key=SIGNER, signature="bad")
    assert str(error.value) == (
        "The claim signature is invalid; regenerate it with the controller key and retry."
    )
