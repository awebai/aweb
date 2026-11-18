"""A staged SDK Item with confirmed metadata; production custody and opening stay real."""

import secrets
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from onepassword import Client, Item

from aweb_secrets import records
from aweb_secrets.secret import SecretRecord
from tests.custody.test_onepassword import ITEM, VAULT, field, reference, sdk_item
from tests.test_production_bootstrap import enrolled_owner
from tests.test_use_approvals import SECRET


@dataclass(kw_only=True, repr=False)
class VaultItem:
    current: Item
    reads: list[int]

    async def get(self, vault_id: str, item_id: str) -> Item:
        if (vault_id, item_id) != (VAULT, ITEM):
            raise ValueError("the SDK was asked for an unexpected immutable item")
        self.reads.append(self.current.version)
        return self.current


@pytest.fixture
async def backend_secret(root, monkeypatch):
    """Stage through the actual console; confirmed configuration is fixture state."""
    service, client, configured, member, installed, *_ = root
    owner = await enrolled_owner(root)
    item = VaultItem(current=sdk_item([field("credential", secrets.token_urlsafe(32))]), reads=[])

    async def authenticate(*, auth: str, integration_name: str, integration_version: str):
        return SimpleNamespace(items=item)

    monkeypatch.setattr(Client, "authenticate", authenticate)
    prefix = configured.console_origin + "/installations/" + installed["installation_id"]
    headers = {"X-CSRF-Token": owner.csrf_token}
    token = await client.post(
        prefix + "/backend-credentials/onepassword/versions",
        json={"value": secrets.token_urlsafe(32)},
        headers=headers,
    )
    assert token.status_code == 201, "the actual console must stage the backend credential"
    record = SecretRecord.from_after({**SECRET, "backend": "onepassword"})
    staged = await client.post(
        prefix + "/onepassword/references",
        json={
            "secret": record.after,
            "reference": reference().as_config(),
            "credential_version": token.json()["version"],
        },
        headers=headers,
    )
    assert staged.status_code == 201, "the actual console must observe and pin the SDK Item"
    async with service.runtime.db().transaction() as tx:
        await records.create_secret(tx, installed["installation_id"], member.team_id, record)
        await records.set_active_version(
            tx,
            installed["installation_id"],
            member.team_id,
            record.secret_id,
            staged.json()["version"],
        )
        await tx.execute(
            "UPDATE onepassword_credentials SET active_version=$1"
            " WHERE installation_id=$2 AND team_id=$3",
            token.json()["version"],
            installed["installation_id"],
            member.team_id,
        )
    return item, record
