"""The actual SDK item model and authentication boundary, with generated canaries."""

import os
from datetime import UTC, datetime

import pytest
from onepassword import Item, ItemCategory, ItemField, ItemFieldType

from aweb_secrets.custody import CustodyUnavailable, Plaintext, encode_value
from aweb_secrets.custody.onepassword import (
    OnePasswordReference,
    OnePasswordSDK,
    SecretVersionChanged,
    project_item,
)

VAULT = "a" * 26
ITEM = "b" * 26


def reference(kind="bearer", fields=None):
    return OnePasswordReference.from_config(
        kind,
        {
            "vault_id": VAULT,
            "item_id": ITEM,
            "fields": fields if fields is not None else {"value": "credential"},
        },
    )


def sdk_item(fields=None, **changes):
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return Item(
        **{
            "id": ITEM,
            "vault_id": VAULT,
            "title": "Test item",
            "category": ItemCategory.APICREDENTIALS,
            "fields": fields or [],
            "sections": [],
            "notes": "",
            "tags": [],
            "websites": [],
            "version": 7,
            "files": [],
            "created_at": now,
            "updated_at": now,
            **changes,
        }
    )


def field(field_id, value):
    return ItemField(
        id=field_id, title="Credential", field_type=ItemFieldType.CONCEALED, value=value
    )


def assert_value(actual, expected):
    # Keep generated credential bytes out of pytest's assertion argument rendering.
    if actual.reveal() != expected:
        raise AssertionError("credential bytes differ")


@pytest.mark.parametrize(
    "kind,fields",
    [
        ("bearer", {"value": "credential"}),
        ("basic", {"username": "username", "password": "password"}),
        ("header", {"value": "credential"}),
        ("query", {"value": "credential"}),
        ("oauth2-client-credentials", {"client_id": "id", "client_secret": "credential"}),
        ("aws-sigv4", {"access_key_id": "id", "secret_access_key": "credential"}),
    ],
)
async def test_item_projection_uses_only_exact_fields_and_shared_codec(kind, fields):
    values = {name: os.urandom(24).hex() for name in fields}
    item = sdk_item(
        [field(selector, values[name]) for name, selector in fields.items()]
        + [field("unselected", os.urandom(24).hex())]
    )
    opened = project_item(reference(kind, fields), item, expected_item_version=7)
    assert opened.item_version == 7
    assert opened.updated_at == item.updated_at.replace(tzinfo=UTC)
    assert_value(opened.value, encode_value(kind, values))
    output = repr(opened) + str(opened.value)
    assert not any(value in output for value in values.values())


@pytest.mark.parametrize(
    "change",
    [
        {"vault_id": "a vault name"},
        {"item_id": "../other"},
        {"fields": {"value": ""}},
        {"fields": {"value": "section/field"}},
        {"fields": {"unexpected": "credential"}},
        {"fields": {}},
        {"extra": "ignored"},
    ],
)
def test_reference_refuses_ambiguous_or_unexpected_configuration(change):
    with pytest.raises(CustodyUnavailable):
        OnePasswordReference.from_config(
            "bearer",
            {
                "vault_id": VAULT,
                "item_id": ITEM,
                "fields": {"value": "credential"},
                **change,
            },
        )


def test_reference_copies_and_freezes_mapping():
    config = {"vault_id": VAULT, "item_id": ITEM, "fields": {"value": "credential"}}
    ref = OnePasswordReference.from_config("bearer", config)
    config["fields"]["value"] = "other"
    ref_config = ref.as_config()
    assert ref_config["fields"] == {"value": "credential"}
    ref_config["fields"]["value"] = "other"
    assert ref.as_config()["fields"] == {"value": "credential"}


@pytest.mark.parametrize(
    "problem", ["missing", "duplicate", "empty", "wrong_item", "wrong_vault", "version"]
)
def test_projection_refuses_unusable_items_without_value_in_error(problem):
    canary = os.urandom(24).hex()
    fields = [field("credential", canary)]
    metadata = {}
    if problem == "missing":
        fields = [field("other", canary)]
    elif problem == "duplicate":
        fields.append(field("credential", canary))
    elif problem == "empty":
        fields = [field("credential", "")]
    elif problem == "wrong_item":
        metadata["id"] = "c" * 26
    elif problem == "wrong_vault":
        metadata["vault_id"] = "c" * 26
    elif problem == "version":
        metadata["version"] = 0
    with pytest.raises(CustodyUnavailable) as refused:
        project_item(reference(), sdk_item(fields, **metadata))
    output = str(refused.value) + repr(refused.value)
    assert canary not in output


def test_item_version_change_reports_only_the_observed_version():
    canary = os.urandom(24).hex()
    with pytest.raises(SecretVersionChanged) as refused:
        project_item(reference(), sdk_item([field("credential", canary)]), expected_item_version=6)
    assert refused.value.code == "secret_version_changed"
    assert refused.value.observed_item_version == 7
    assert canary not in str(refused.value) + repr(refused.value)


async def test_real_sdk_authentication_failure_keeps_token_out_of_errors_and_output(capfd):
    token = os.urandom(24).hex()
    sdk = OnePasswordSDK()
    with pytest.raises(CustodyUnavailable) as refused:
        await sdk.read(reference(), token=Plaintext(encode_value("bearer", {"value": token})))
    captured = capfd.readouterr()
    output = str(refused.value) + repr(refused.value) + captured.out + captured.err
    assert token not in output
    assert refused.value.code == "custody_unavailable"
