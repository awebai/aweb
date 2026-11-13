"""A real requester proof follows the fixture's selected external origin."""

import base64
import json
from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import ProtectedKeyContext
from nacl.signing import SigningKey

from tests.test_independent_protected_signer import DOMAIN, ORIGIN, SERVICE, TEAM, did, proof_request


@pytest.mark.parametrize("origin", [ORIGIN, "http://127.0.0.1:31415"])
def test_request_proof_uses_the_worlds_external_origin(origin):
    key = SigningKey.generate()
    context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, "did:aw:human", DOMAIN, 1)
    world = SimpleNamespace(root=key, context=context, request_origin=origin)
    request = proof_request(world, body=b"{}")
    encoded = request.headers["x-aweb-signed-payload"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert json.loads(raw)["aud"] == origin
    scheme, issuer, signature = request.headers["authorization"].split()
    assert scheme == "DIDKey" and issuer == did(key)
    key.verify_key.verify(raw, base64.b64decode(signature + "=" * (-len(signature) % 4)))
