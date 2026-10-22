"""The console-only 1Password change projections; syntax grants no authority."""

import copy

import pytest

from aweb_secrets.change import ChangeRefused, covered_bytes, validate_change
from aweb_secrets.change_sets import APPLICABLE_KINDS
from tests.test_change import POLICY, _change, _member
from tests.test_change_sets import World
from tests.test_change_sets import world as _world

world = _world

TOKEN = {
    "kind": "backend_credential",
    "op": "create",
    "ref": "onepassword",
    "after": {"v": 1, "backend": "onepassword", "credential_id": "bkc_onepassword", "version": 3},
}
BINDING = {
    "kind": "onepassword_binding",
    "op": "create",
    "ref": "sec_19ab42",
    "after": {
        "v": 1,
        "secret_id": "sec_19ab42",
        "version": 4,
        "credential_version": 3,
        "vault_id": "a" * 26,
        "item_id": "b" * 26,
        "fields": {"value": "credential"},
        "item_version": 7,
    },
}


def test_console_can_describe_the_exact_immutable_versions():
    validate_change(_change(changes=[TOKEN, BINDING]))
    assert not {"backend_credential", "onepassword_binding"} & APPLICABLE_KINDS


@pytest.mark.parametrize("item", [TOKEN, BINDING])
def test_team_auth_cannot_draft_backend_credentials_or_references(item):
    with pytest.raises(ChangeRefused) as refused:
        validate_change(_change(changes=[item], drafter=_member()))
    assert refused.value.code == "console_required"


@pytest.mark.parametrize("item", [TOKEN, BINDING])
def test_versions_cannot_be_updated_in_place(item):
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[{**item, "op": "update"}]))


@pytest.mark.parametrize(
    "key,value",
    [
        ("version", 0),
        ("version", True),
        ("credential_version", 0),
        ("item_version", True),
        ("item_version", -1),
        ("secret_id", "bkc_onepassword"),
        ("vault_id", "vault title"),
        ("item_id", "../other"),
        ("fields", {}),
        ("fields", {"unknown": "field"}),
        ("fields", {"value": "bad/selector"}),
        ("fields", {"value": "\x00"}),
        ("fields", {"value": "field", "password": "other"}),
        ("fields", {"username": "field"}),
        ("fields", {"value": 42}),
        ("fields", ["value"]),
    ],
)
def test_binding_refuses_malformed_metadata(key, value):
    item = copy.deepcopy(BINDING)
    item["after"][key] = value
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize(
    "fields",
    [
        {"value": "credential"},
        {"username": "user", "password": "credential"},
        {"client_id": "client", "client_secret": "credential"},
        {"access_key_id": "key", "secret_access_key": "credential"},
        {"access_key_id": "key", "secret_access_key": "credential", "session_token": "token"},
    ],
)
def test_fields_use_one_complete_supported_codec_family(fields):
    item = copy.deepcopy(BINDING)
    item["after"]["fields"] = fields
    validate_change(_change(changes=[item]))


@pytest.mark.parametrize(
    "key,value", [("backend", "native"), ("credential_id", "sec_19ab42"), ("version", 0)]
)
def test_credential_binding_is_reserved_and_native_versioned(key, value):
    item = copy.deepcopy(TOKEN)
    item["after"][key] = value
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize("item", [TOKEN, BINDING])
def test_no_value_or_hash_can_be_added_to_the_approval(item):
    altered = copy.deepcopy(item)
    altered["after"]["value_sha256"] = "0" * 64
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[altered]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("credential_version", 5),
        ("item_version", 8),
        ("item_id", "c" * 26),
        ("fields", {"value": "other"}),
    ],
)
def test_all_binding_selectors_and_versions_are_covered_by_the_approval(field, value):
    original = _change(changes=[TOKEN, BINDING])
    changed = copy.deepcopy(original)
    changed["changes"][1]["after"][field] = value
    assert covered_bytes(original, POLICY) != covered_bytes(changed, POLICY)


@pytest.mark.parametrize("item", [TOKEN, BINDING])
async def test_unimplemented_bindings_cannot_mint_or_persist_a_draft(world: World, item):
    async with world.db.transaction() as tx:
        with pytest.raises(ChangeRefused) as refused:
            await world.change_sets.draft(tx, _change(changes=[item]))
        assert refused.value.code == "change_kind_not_applicable"
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0
