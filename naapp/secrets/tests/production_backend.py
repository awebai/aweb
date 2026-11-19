"""A staged SDK Item with confirmed metadata; production custody and opening stay real."""

import secrets

import pytest

from aweb_secrets import records
from aweb_secrets.secret import SecretBackend, SecretRecord
from tests.custody.test_onepassword import field, reference, sdk_item
from tests.test_production_bootstrap import enrolled_owner
from tests.test_use_approvals import SECRET
from tests.value_sources import Vault, VaultItem


@pytest.fixture
async def backend_secret(root, onepassword_values):
    """Stage through the actual console; confirmed configuration is fixture state."""
    service, client, configured, member, installed, *_ = root
    owner = await enrolled_owner(root)
    item = VaultItem(current=sdk_item([field("credential", secrets.token_urlsafe(32))]))
    vault = Vault(items={(item.current.vault_id, item.current.id): item})
    onepassword_values.vaults[(installed["installation_id"], member.team_id)] = vault
    prefix = configured.console_origin + "/installations/" + installed["installation_id"]
    headers = {"X-CSRF-Token": owner.csrf_token}
    token = await client.post(
        prefix + "/backend-credentials/onepassword/versions",
        json={"value": vault.token},
        headers=headers,
    )
    assert token.status_code == 201, "the actual console must stage the backend credential"
    record = SecretRecord.from_after({**SECRET, "backend": SecretBackend.ONEPASSWORD})
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
