"""Software WebAuthn device for real crypto/storage unit controls, not a browser.

It claims passkey UV only. The joined journey uses Chromium's authenticator.
"""

import hashlib
import json
import secrets

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.wire import domain


class Passkey:
    def __init__(self, origin, rp_id):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.identifier = secrets.token_bytes(32)
        self.origin, self.rp_id = origin, rp_id

    def client_data(self, kind, challenge):
        return json.dumps(
            {
                "type": kind,
                "challenge": encode(challenge),
                "origin": self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    def register(self, challenge):
        public = self.key.public_key().public_numbers()
        cose = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32), -3: public.y.to_bytes(32)}
        )
        auth = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + b"\x45"
            + bytes(4)
            + bytes(16)
            + len(self.identifier).to_bytes(2)
            + self.identifier
            + cose
        )
        return {
            "id": encode(self.identifier),
            "client_data_json": encode(self.client_data("webauthn.create", challenge)),
            "attestation_object": encode(
                cbor2.dumps({"fmt": "none", "authData": auth, "attStmt": {}})
            ),
        }

    def assert_request(self, request):
        digest = hashlib.sha256(domain("request") + canonical(request)).digest()
        client = self.client_data("webauthn.get", digest)
        auth = hashlib.sha256(self.rp_id.encode()).digest() + b"\x05" + bytes(4)
        signature = self.key.sign(
            auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": encode(self.identifier),
            "client_data_json": encode(client),
            "authenticator_data": encode(auth),
            "signature": encode(signature),
        }
