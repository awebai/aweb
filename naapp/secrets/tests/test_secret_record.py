"""The secret record v1: the owner-set, non-secret description of a secret (§6.2, §7.5)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from aweb_secrets.principal import is_principal
from aweb_secrets.secret import KINDS, SecretInvalid, SecretRecord, mint_secret_id

RECORD = {
    "v": 1,
    "secret_id": "sec_19ab42",
    "ref": "payments-live",
    "description": "Live payments API key",
    "kind": "header",
    "kind_params": {"name": "X-Api-Key", "prefix": ""},
    "sensitivity": "sensitive",
    "approve_only": False,
    "backend": "native",
}

KIND_PARAMS = {
    "bearer": {},
    "basic": {},
    "header": {"name": "X-Api-Key", "prefix": "Token "},
    "query": {"param": "api_key"},
    "aws-sigv4": {"region": "eu-west-1", "service": "sts"},
}


def _record(**changes):
    record = copy.deepcopy(RECORD)
    record.update(changes)
    return record


def test_the_kinds_are_the_six_auth_schemes() -> None:
    assert KINDS == (
        "bearer",
        "basic",
        "header",
        "query",
        "oauth2-client-credentials",
        "aws-sigv4",
    )


@pytest.mark.parametrize(("kind", "params"), sorted(KIND_PARAMS.items()))
def test_each_kind_takes_its_own_parameters(kind, params) -> None:
    record = SecretRecord.from_after(_record(kind=kind, kind_params=params))
    assert (record.kind, record.kind_params) == (kind, params)


def test_the_record_round_trips_as_its_after() -> None:
    assert SecretRecord.from_after(RECORD).after == RECORD


@pytest.mark.parametrize(
    "change",
    [
        {"v": 2},
        {"v": True},
        {"kind": "api_key"},
        {"kind": "bearer", "kind_params": {"name": "X-Api-Key"}},
        {"kind_params": {"name": "X-Api-Key"}},
        {"kind_params": {"name": "Host", "prefix": ""}},
        {"kind_params": {"name": "Content-Length", "prefix": ""}},
        {"kind_params": {"name": "X Api Key", "prefix": ""}},
        {"kind_params": {"name": "X-Api-Key", "prefix": "a\nb"}},
        {"kind": "query", "kind_params": {"param": "api key"}},
        {"kind": "aws-sigv4", "kind_params": {"region": "EU-WEST-1", "service": "sts"}},
        {"kind": "aws-sigv4", "kind_params": {"region": "eu-west-1"}},
        {"ref": "Payments Live"},
        {"ref": ""},
        {"secret_id": "19ab42"},
        {"description": "x" * 513},
        {"description": "bad‮control"},
        {"sensitivity": "secret"},
        {"approve_only": "no"},
        {"backend": "vault"},
        {"surprise": True},
    ],
)
def test_a_malformed_record_is_refused(change) -> None:
    with pytest.raises(SecretInvalid):
        SecretRecord.from_after(_record(**change))


@pytest.mark.parametrize("missing", sorted(RECORD))
def test_every_field_is_required(missing) -> None:
    record = copy.deepcopy(RECORD)
    del record[missing]
    with pytest.raises(SecretInvalid):
        SecretRecord.from_after(record)


def test_approve_only_implies_sensitive() -> None:
    with pytest.raises(SecretInvalid):
        SecretRecord.from_after(_record(approve_only=True, sensitivity="standard"))
    assert SecretRecord.from_after(_record(approve_only=True)).approve_only


def test_minted_ids_are_distinct_valid_secret_ids() -> None:
    ids = {mint_secret_id() for _ in range(100)}
    assert len(ids) == 100
    for secret_id in ids:
        assert SecretRecord.from_after(_record(secret_id=secret_id)).secret_id == secret_id


VECTORS = Path(__file__).parents[1] / "vectors"


def _secret_kinds_in(node) -> set[str]:
    if isinstance(node, dict):
        found = {node["kind"]} if "secret_id" in node and "kind" in node else set()
        return found.union(*(_secret_kinds_in(value) for value in node.values()))
    if isinstance(node, list):
        return set().union(*(_secret_kinds_in(value) for value in node))
    return set()


@pytest.mark.parametrize("vector", ["use-approval-v1.json", "change-v1.json"])
def test_every_secret_kind_in_the_vectors_is_an_auth_scheme(vector) -> None:
    cases = json.loads((VECTORS / vector).read_text())["positive_cases"]
    kinds = _secret_kinds_in(cases)
    assert kinds
    assert kinds <= set(KINDS)


def test_use_approval_requesters_are_principals() -> None:
    cases = json.loads((VECTORS / "use-approval-v1.json").read_text())["positive_cases"]
    requesters = [case["request"]["requester"]["principal"] for case in cases]
    assert requesters and all(is_principal(principal) for principal in requesters)
