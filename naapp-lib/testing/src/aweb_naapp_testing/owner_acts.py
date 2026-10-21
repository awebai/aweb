"""Real team owner acts for tests.

The team key is registered in the tests' AWID registry, and every act is a
signed ``aweb.owner-act/1`` verified by the real K2 verifier, its nonce
consumed in the transaction that applies the act's effect.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from nacl.signing import SigningKey
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.owner_act import APP_ACTS, PREFIX, VerifiedOwnerAct
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, PreparedOwnerAct
from aweb_naapp.hooks.strictjson import canonical
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp_testing import did_key

TEAM_ID = "demo:example.com"
AUDIENCE = "https://app.example.com"
APP_ID = "example"
INSTALLATION_ID = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"


@dataclass
class TeamOwner:
    """The team's owner: signs acts with the team key the registry knows."""

    team_key: SigningKey
    verifier: OwnerActVerifier

    def sign(self, act: str, subject: dict[str, Any]) -> tuple[bytes, str]:
        issued = datetime.now(UTC).replace(microsecond=0)
        fields = {
            "v": 1,
            "type": "aweb.owner-act",
            "act": act,
            "team_id": TEAM_ID,
            "aud": AUDIENCE,
            "team_key_did": did_key(self.team_key),
            "subject": subject,
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (issued + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": secrets.token_hex(16),
        }
        signing = PREFIX + canonical(fields)
        signature = base64.b64encode(self.team_key.sign(signing).signature).decode().rstrip("=")
        return signing, signature

    async def prepare(self, act: str, subject: dict[str, Any]) -> PreparedOwnerAct:
        signing, signature = self.sign(act, subject)
        return await self.verifier.prepare(signing, signature, team_id=TEAM_ID)

    async def consume(
        self, tx: TransactionManager, prepared: PreparedOwnerAct, subject: dict[str, Any]
    ) -> VerifiedOwnerAct:
        return await self.verifier.consume_in(tx, prepared, expected_subject=subject)


def designation_subject(scope: str, contact: str) -> dict[str, Any]:
    """The subject of an act that designates, or recovers, ``scope``'s approver."""
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": contact_sha256(contact),
    }


def revocation_subject(scope: str, subject_ref: str) -> dict[str, Any]:
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "subject_ref": subject_ref,
    }


async def team_owner(registry) -> TeamOwner:
    key = SigningKey.generate()
    await registry.add_team(TEAM_ID, did_key(key))
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=0,
        service_token=SERVICE_TOKEN,
        transport=registry.transport,
    )

    async def current_team_key(team_id: str) -> str:
        return (await cache.get(team_id)).team_did_key

    verifier = OwnerActVerifier(
        scope=APP_ID, audience=AUDIENCE, acts=APP_ACTS, team_key_for=current_team_key
    )
    return TeamOwner(team_key=key, verifier=verifier)
