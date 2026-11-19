"""The SDK boundary preserves fresh item reads and the production version pin."""

import secrets

import pytest

from aweb_secrets.custody import OpenedBackendCredential, Plaintext, SealContext, encode_value
from aweb_secrets.custody.onepassword import OnePasswordSDK, SecretVersionChanged
from aweb_secrets.secret import SecretKind
from tests.custody.test_onepassword import ITEM, VAULT, field, reference, sdk_item
from tests.value_sources import Vault, VaultItem


async def test_sdk_reopens_the_item_and_refuses_a_changed_pinned_version(onepassword_values):
    vault = Vault()
    item = VaultItem(current=sdk_item([field("credential", secrets.token_urlsafe(32))]))
    vault.items[(VAULT, ITEM)] = item
    onepassword_values.vaults[("installation", "team:example.com")] = vault
    credential = OpenedBackendCredential(
        context=SealContext("installation", "team:example.com", "bkc_onepassword", 1),
        plaintext=Plaintext(encode_value(SecretKind.BEARER, {"value": vault.token})),
    )
    sdk = OnePasswordSDK()
    observed = await sdk.read(reference(), credential=credential)
    assert observed.item_version == 7
    item.current = sdk_item([field("credential", secrets.token_urlsafe(32))], version=8)
    with pytest.raises(SecretVersionChanged):
        await sdk.read(reference(), credential=credential, expected_item_version=7)
    fresh = await sdk.read(reference(), credential=credential, expected_item_version=8)
    assert fresh.item_version == 8
    assert item.reads == [7, 8, 8]
