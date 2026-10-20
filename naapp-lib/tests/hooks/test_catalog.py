"""The aweb.hooks catalog vector, read through the strict catalog reader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aweb_naapp.hooks.catalog import CatalogError, PayloadRefused, load_catalog

AWEB_ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json"
CATALOG_BYTES = CATALOG_PATH.read_bytes()
VECTOR = json.loads(CATALOG_BYTES)
CATALOG = load_catalog(CATALOG_BYTES)

HOOKS = (
    "post-secret-use-hook",
    "post-governance-hook",
    "post-manifest-command-hook",
    "post-mutation-hook",
    "post-command-hook",
)


def _payload(case: dict):
    if "payload_json" in case:
        return json.loads(case["payload_json"])
    return case["payload"]


def _mutated(change) -> bytes:
    document = json.loads(CATALOG_BYTES)
    change(document)
    return json.dumps(document).encode()


def test_catalog_names_the_five_v1_hooks() -> None:
    assert (CATALOG.id, CATALOG.version) == ("aweb.hooks", 1)
    assert tuple(CATALOG.hooks) == HOOKS
    classes = {name: hook.hook_class for name, hook in CATALOG.hooks.items()}
    assert classes == {
        "post-secret-use-hook": "server",
        "post-governance-hook": "server",
        "post-manifest-command-hook": "server",
        "post-mutation-hook": "server",
        "post-command-hook": "client",
    }
    producers = {name: hook.producer_kinds for name, hook in CATALOG.hooks.items()}
    assert producers == {
        "post-secret-use-hook": ("app",),
        "post-governance-hook": ("app",),
        "post-manifest-command-hook": ("app",),
        "post-mutation-hook": ("core",),
        "post-command-hook": ("client",),
    }


def test_specific_hooks_supersede_the_manifest_command_hook() -> None:
    assert CATALOG.superseded_by("post-manifest-command-hook") == (
        "post-secret-use-hook",
        "post-governance-hook",
    )
    assert CATALOG.superseded_by("post-mutation-hook") == ()


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda case: case["name"])
def test_positive_case_validates(case) -> None:
    CATALOG.validate(case["hook"], _payload(case))


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda case: case["name"])
def test_negative_case_is_refused_with_its_fault(case) -> None:
    with pytest.raises(PayloadRefused) as refused:
        CATALOG.validate(case["hook"], _payload(case))
    assert refused.value.code == case["error"]
    assert refused.value.field == case.get("field")


def test_secret_use_dispositions_and_refusal_codes() -> None:
    fields = CATALOG.hooks["post-secret-use-hook"].fields
    assert fields["disposition"].enum == ("returned", "withheld", "stored_as_secret")
    refusal_codes = fields["refusal_code"].enum
    assert len(refusal_codes) == 28
    assert len(set(refusal_codes)) == 28
    assert {"audit_target_unavailable", "audit_delivery_stalled"} <= set(refusal_codes)


def test_every_governance_act_has_one_direction() -> None:
    hook = CATALOG.hooks["post-governance-hook"]
    assert set(hook.act_directions) == set(hook.fields["act"].enum)
    assert set(hook.act_directions.values()) == {"widening", "narrowing"}


def test_audit_critical_follows_the_catalog() -> None:
    assert CATALOG.is_audit_critical("post-secret-use-hook", {"action": "refused"})
    assert CATALOG.is_audit_critical("post-governance-hook", {"act": "grant.created"})
    assert not CATALOG.is_audit_critical("post-governance-hook", {"act": "grant.revoked"})
    assert not CATALOG.is_audit_critical("post-governance-hook", {"act": "installation.disabled"})
    assert not CATALOG.is_audit_critical("post-manifest-command-hook", {})
    assert not CATALOG.is_audit_critical("post-mutation-hook", {"mutation_type": "task.created"})
    assert not CATALOG.is_audit_critical("post-command-hook", {})


def test_mutation_types_include_key_revocation_and_exclude_operational_events() -> None:
    hook = CATALOG.hooks["post-mutation-hook"]
    assert "app_key.revoked" in hook.types
    assert set(hook.types["app_key.revoked"].fields) == {
        "mutation_type",
        "target_ref",
        "before_ref",
        "after_ref",
        "app_id",
        "kid",
        "purposes",
    }
    assert not {"reservation.acquired", "agent.status"} & set(hook.types)


def test_payload_must_be_a_flat_object() -> None:
    with pytest.raises(PayloadRefused) as refused:
        CATALOG.validate("post-mutation-hook", ["task.created"])
    assert refused.value.code == "invalid_value"
    with pytest.raises(PayloadRefused) as refused:
        CATALOG.validate(
            "post-secret-use-hook", {"action": "admitted", "op_kind": "broker", "secret_id": None}
        )
    assert (refused.value.code, refused.value.field) == ("invalid_value", "secret_id")


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update({"extra": 1}),
        lambda d: d["scheme"].update({"extra": "x"}),
        lambda d: d["catalog"].update({"extra": "x"}),
        lambda d: d["types"]["ref"].update({"extra": "x"}),
        lambda d: d["hooks"]["post-command-hook"].update({"extra": "x"}),
        lambda d: d["hooks"]["post-secret-use-hook"]["fields"]["action"].update({"extra": "x"}),
        lambda d: d["hooks"]["post-secret-use-hook"]["rules"][0].update({"extra": "x"}),
        lambda d: d["hooks"]["post-secret-use-hook"]["rules"][0]["when"].update({"extra": "x"}),
        lambda d: d["hooks"]["post-mutation-hook"]["types"]["task.created"].update({"extra": "x"}),
        lambda d: d["precedence"][0].update({"extra": "x"}),
    ],
    ids=[
        "top",
        "scheme",
        "catalog",
        "type",
        "hook",
        "field",
        "rule",
        "rule-when",
        "mutation-type",
        "precedence",
    ],
)
def test_reader_refuses_an_unknown_key_at_every_level(change) -> None:
    with pytest.raises(CatalogError):
        load_catalog(_mutated(change))


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["hooks"]["post-secret-use-hook"]["fields"]["secret_id"].update(
            {"type": "nope"}
        ),
        lambda d: d["hooks"]["post-secret-use-hook"]["rules"][0].update({"require": ["nope"]}),
        lambda d: d["hooks"]["post-governance-hook"]["act_directions"].pop("grant.created"),
        lambda d: d["hooks"]["post-governance-hook"]["act_directions"].update(
            {"grant.created": "sideways"}
        ),
        lambda d: d["hooks"]["post-command-hook"]["command_classes"]["identity_key"].append("nope"),
        lambda d: d["precedence"][0].update({"specific": "post-nothing-hook"}),
        lambda d: d["catalog"].update({"version": 1.0}),
        lambda d: d["types"].update({"bad": {"kind": "string", "pattern": "("}}),
    ],
    ids=[
        "unknown-type",
        "rule-names-unknown-field",
        "act-without-direction",
        "unknown-direction",
        "class-effect-not-in-enum",
        "precedence-unknown-hook",
        "float-version",
        "bad-pattern",
    ],
)
def test_reader_refuses_an_inconsistent_catalog(change) -> None:
    with pytest.raises(CatalogError):
        load_catalog(_mutated(change))


def test_reader_refuses_duplicate_keys() -> None:
    duplicated = CATALOG_BYTES.replace(
        b'"name": "hook-catalog-v1",', b'"name": "a", "name": "b",', 1
    )
    with pytest.raises(CatalogError):
        load_catalog(duplicated)
