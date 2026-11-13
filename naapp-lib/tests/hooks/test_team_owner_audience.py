"""Both generations of the fixture signer bind the actual human audience."""

import base64
import json

import pytest
from aweb_naapp_testing import did_key
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TeamOwner
from awid.did import stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, PREFIX
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier

HUMAN = "https://console.example.com"


def signer():
    key = SigningKey.generate()

    async def current_key(team_id):
        return did_key(key)

    verifier = OwnerActVerifier(
        scope=APP_ID, audience=HUMAN, acts=HUMAN_ROLE_ACTS, team_key_for=current_key
    )
    return TeamOwner(key, verifier, team_key_for=current_key)


def signed_audience(owner):
    signing, signature = owner.sign(
        "human-role.revoke",
        {
            "app_id": APP_ID,
            "installation_id": INSTALLATION_ID,
            "role": "example.owner",
            "principal": stable_id_from_public_key(bytes(owner.team_key.verify_key)),
        },
    )
    owner.team_key.verify_key.verify(
        signing, base64.b64decode(signature + "=" * (-len(signature) % 4))
    )
    return json.loads(signing[len(PREFIX) :])["aud"]


def test_an_existing_verifiers_audience_survives_the_new_default_field():
    assert signed_audience(signer()) == HUMAN


def test_a_sign_only_owner_uses_its_explicit_audience_without_a_verifier():
    owner = TeamOwner(SigningKey.generate(), None, audience=HUMAN)
    assert signed_audience(owner) == HUMAN


@pytest.mark.parametrize("override", [None, "https://another-console.example.com"])
def test_changing_the_vocabulary_preserves_or_explicitly_changes_the_audience(override):
    owner = signer().for_acts(HUMAN_ROLE_ACTS, audience=override)
    assert signed_audience(owner) == (override or HUMAN)
