"""Official SDK boundary data for worlds that exercise real reference custody.

Only authentication and Items.get are substituted (§6.1/§5.3). Values reach
dispatch through the production observation, binding, pin and reopen path.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from types import SimpleNamespace

from onepassword import Item
from pgdbm import AsyncDatabaseManager

from aweb_secrets import records
from aweb_secrets.custody import Custody, SealContext, encode_value
from aweb_secrets.custody.onepassword import OnePasswordReference, OnePasswordSDK
from aweb_secrets.secret import SecretBackend, SecretKind, SecretRecord
from tests.custody.test_onepassword import VAULT, sdk_item
from tests.custody.test_onepassword import field as item_field


@dataclass(kw_only=True, repr=False)
class VaultItem:
    current: Item
    reads: list[int] = field(default_factory=list)

    async def get(self, *, vault_id: str, item_id: str) -> Item:
        if (vault_id, item_id) != (self.current.vault_id, self.current.id):
            raise AssertionError("the SDK requested different immutable selectors")
        self.reads.append(self.current.version)
        return self.current


@dataclass(kw_only=True, repr=False)
class Vault:
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    credential: SealContext | None = None
    items: dict[tuple[str, str], VaultItem] = field(default_factory=dict)

    async def get(self, *, vault_id: str, item_id: str) -> Item:
        item = self.items.get((vault_id, item_id))
        if item is None:
            raise AssertionError("the SDK requested an unstaged item")
        return await item.get(vault_id=vault_id, item_id=item_id)


@dataclass(kw_only=True, repr=False)
class OnePasswordValues:
    vaults: dict[tuple[str, str], Vault] = field(default_factory=dict)

    async def authenticate(self, *, auth: str, integration_name: str, integration_version: str):
        for vault in self.vaults.values():
            if secrets.compare_digest(auth, vault.token):
                return SimpleNamespace(items=vault)
        raise AssertionError("the SDK did not receive the staged service credential")

    def item(self, *, installation_id: str, team_id: str, secret_id: str) -> VaultItem:
        vault = self.vaults[(installation_id, team_id)]
        return vault.items[(VAULT, self._item_id(secret_id))]

    @staticmethod
    def _item_id(secret_id: str) -> str:
        return hashlib.sha256(secret_id.encode()).hexdigest()[:26]

    async def activate(
        self,
        *,
        db: AsyncDatabaseManager,
        custody: Custody,
        installation_id: str,
        team_id: str,
        record: SecretRecord,
        values: dict[str, str],
    ) -> SealContext:
        """Observe a real SDK Item, stage its reference, then seed confirmed metadata."""
        if record.backend != SecretBackend.ONEPASSWORD:
            raise AssertionError("reference worlds require a 1Password record")
        vault = self.vaults.setdefault((installation_id, team_id), Vault())
        credential = await self._credential(
            db=db, custody=custody, vault=vault, installation_id=installation_id, team_id=team_id
        )
        item_id = self._item_id(record.secret_id)
        vault.items[(VAULT, item_id)] = VaultItem(
            current=sdk_item(
                [item_field(name, value) for name, value in values.items()], id=item_id
            )
        )
        reference = OnePasswordReference.from_config(
            record.kind,
            {"vault_id": VAULT, "item_id": item_id, "fields": {name: name for name in values}},
        )
        observed = await OnePasswordSDK().read(
            reference, credential=await custody.backend_credential_opener.open(credential)
        )
        async with db.transaction() as tx:
            staged = await custody.stage_onepassword_reference(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                secret_id=record.secret_id,
                observed=observed,
                initial=record,
            )
            await records.set_active_version(
                tx, installation_id, team_id, record.secret_id, staged.context.version
            )
        return staged.context

    @staticmethod
    async def _credential(
        *,
        db: AsyncDatabaseManager,
        custody: Custody,
        vault: Vault,
        installation_id: str,
        team_id: str,
    ) -> SealContext:
        if vault.credential is None:
            async with db.transaction() as tx:
                vault.credential = await custody.stage_backend_credential(
                    tx,
                    installation_id=installation_id,
                    team_id=team_id,
                    value=encode_value(SecretKind.BEARER, {"value": vault.token}),
                )
                await tx.execute(
                    "UPDATE {{tables.onepassword_credentials}} SET active_version=$1"
                    " WHERE installation_id=$2 AND team_id=$3",
                    vault.credential.version,
                    installation_id,
                    team_id,
                )
        return vault.credential
