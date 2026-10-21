"""A software WebAuthn authenticator for tests.

It answers the server's real options with real ceremonies: a P-256 credential
key, CBOR authenticator data, a `packed` self-attestation and ES256 assertion
signatures over authenticator data and the client data hash, as a platform
authenticator and browser would produce them. The verifier under test checks
these with py_webauthn exactly as it checks a browser's.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, AT = 0x01, 0x04, 0x40
ES256 = -7


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class SoftCredential:
    credential_id: bytes
    key: ec.EllipticCurvePrivateKey
    rp_id: str
    user_handle: bytes
    sign_count: int = 0

    def cose_public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,
                3: ES256,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )


class SoftAuthenticator:
    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.credentials: dict[bytes, SoftCredential] = {}

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def _sign(self, key: ec.EllipticCurvePrivateKey, auth_data: bytes, client_data: bytes) -> bytes:
        return key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))

    def create(
        self, options: dict, *, origin: str | None = None, user_verified: bool = True
    ) -> dict:
        """navigator.credentials.create() for the server's registration options."""
        rp_id = options["rp"]["id"]
        credential = SoftCredential(
            credential_id=os.urandom(32),
            key=ec.generate_private_key(ec.SECP256R1()),
            rp_id=rp_id,
            user_handle=from_b64url(options["user"]["id"]),
        )
        flags = UP | AT | (UV if user_verified else 0)
        attested = (
            bytes(16)
            + struct.pack(">H", len(credential.credential_id))
            + credential.credential_id
            + credential.cose_public_key()
        )
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", credential.sign_count)
            + attested
        )
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        attestation = cbor2.dumps(
            {
                "fmt": "packed",
                "attStmt": {
                    "alg": ES256,
                    "sig": self._sign(credential.key, auth_data, client_data),
                },
                "authData": auth_data,
            }
        )
        self.credentials[credential.credential_id] = credential
        return {
            "id": b64url(credential.credential_id),
            "rawId": b64url(credential.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        options: dict,
        *,
        origin: str | None = None,
        user_verified: bool = True,
        count_step: int = 1,
    ) -> dict:
        """navigator.credentials.get() for the server's authentication options."""
        allowed = [c for c in self.credentials.values() if c.rp_id == options["rpId"]]
        allow_ids = {item["id"] for item in options.get("allowCredentials", [])}
        if allow_ids:
            allowed = [c for c in allowed if b64url(c.credential_id) in allow_ids] or allowed
        credential = allowed[0]
        credential.sign_count += count_step
        flags = UP | (UV if user_verified else 0)
        auth_data = (
            hashlib.sha256(credential.rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", credential.sign_count)
        )
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        return {
            "id": b64url(credential.credential_id),
            "rawId": b64url(credential.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(self._sign(credential.key, auth_data, client_data)),
                "userHandle": b64url(credential.user_handle),
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def clone(self) -> SoftAuthenticator:
        """A copy holding the same keys and counters, as a cloned device would."""
        twin = SoftAuthenticator(self.origin)
        twin.credentials = {
            cid: SoftCredential(c.credential_id, c.key, c.rp_id, c.user_handle, c.sign_count)
            for cid, c in self.credentials.items()
        }
        return twin
