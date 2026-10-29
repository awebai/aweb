"""The frozen identity-tree vectors driven through the real AWID routes.

Seeds, keys and certificates are the public synthetic material in
docs/vectors/id-certificates-v1.json. Every write goes through the HTTP
routes a real caller uses; nothing here inserts registry rows.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from nacl.bindings import (
    crypto_core_ed25519_add,
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_scalarmult_ed25519_base_noclamp,
)
from nacl.signing import SigningKey

from awid import dns_auth
from awid.did import did_from_public_key
from awid.dns_verify import DnsVerificationError, DomainAuthority
from awid.id_certificates import encode_id_chain_header, id_certificate_signing_bytes
from awid.signing import canonical_json_bytes, sign_message
from awid_service.deps import get_domain_verifier

from conftest import build_signed_headers
from identity_support import register_identity, request_rotation

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs" / "vectors" / "id-certificates-v1.json").read_text()
)
DOMAIN = "example.com"
ORIGIN = "https://registry.example.com"
REGISTER_PATH = "/v1/id-certificates/register"
REVOKE_PATH = "/v1/id-certificates/revoke"
REQUEST_TYPE = "aweb.awid-controller-request"
KEYS = VECTORS["keys"]


def at(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def wire_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def operation_case(name: str) -> dict:
    [case] = [case for case in VECTORS["operation_cases"] if case["name"] == name]
    return case


def seed(key_name: str) -> bytes:
    return bytes.fromhex(KEYS[key_name]["seed_hex"])


def did_key(key_name: str) -> str:
    return KEYS[key_name]["did_key"]


def did_aw(key_name: str) -> str:
    return KEYS[key_name]["did_aw"]


def certificate(name: str) -> dict:
    return copy.deepcopy(VECTORS["certificates"][name]["signed"])


def certificate_id(name: str) -> str:
    return VECTORS["certificates"][name]["certificate_id"]


# Frozen operation cases consumed by a test, by name, across the identity-tree
# test modules (see the partition test in test_id_certificate_registration).
CONSUMED: set[str] = set()


def consumes(*names: str):
    cases = [operation_case(name) for name in names]
    CONSUMED.update(names)

    def decorate(test):
        return pytest.mark.asyncio(pytest.mark.parametrize("case", cases, ids=list(names))(test))

    return decorate


def key_name_for(identity: str) -> str:
    [name] = [name for name, key in KEYS.items() if identity in (key["did_aw"], key["did_key"])]
    return name


def sign(fields: dict, signer: str) -> dict:
    """A certificate the test itself issues with a synthetic vector key."""
    signature = SigningKey(seed(signer)).sign(id_certificate_signing_bytes(fields)).signature
    return {"certificate": fields, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}


def covering_headers(
    signer: str, *, method: str, path: str, body: bytes, domain: str, operation: str,
    new_key_signer: str | None = None, **claims,
) -> dict:
    """A covering-v2 request signed by ``signer``, and by ``new_key_signer`` in the new-key header."""
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {
        "v": 2, "type": REQUEST_TYPE, "aud": ORIGIN, "method": method, "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
        "domain": domain, "operation": operation, **claims,
    }
    raw = canonical_json_bytes(payload)
    headers = {
        "Authorization": f"DIDKey {did_key(signer)} {sign_message(seed(signer), raw)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "Content-Type": "application/json",
    }
    if new_key_signer is not None:
        headers["X-AWEB-New-Key-Authorization"] = (
            f"DIDKey {did_key(new_key_signer)} {sign_message(seed(new_key_signer), raw)}"
        )
    return headers


def chain_header(chain: list[dict]) -> str:
    return encode_id_chain_header({"v": 1, "type": "aweb.id-chain", "certificates": chain})


def did_registration_entry(key_name: str) -> dict:
    """The frozen register_did log entry of a vector identity, from the status fixtures."""
    target = did_aw(key_name)
    for fixture in VECTORS["status_fixtures"].values():
        for identity in fixture["identities"]:
            if identity["id"] == target and identity["key_history"][0]["entry"]["operation"] == "register_did":
                return identity["key_history"][0]["entry"]
    raise KeyError(key_name)


def ed25519_vector_key(name: str) -> str:
    """The did:key of a frozen ed25519_verification public key, such as a small-order one."""
    [case] = [case for case in VECTORS["ed25519_verification"]["cases"] if case["name"] == name]
    return did_from_public_key(bytes.fromhex(case["public_key_hex"]))


class MixedOrderController:
    """A controller key that is an honest key plus an order-8 torsion point.

    It passes did:key syntax and, whenever the signature's hash scalar is a
    multiple of 8, ordinary cofactorless verification too, so a registry that
    only checks those would accept it. ``signed_headers`` searches the
    request timestamp, within the allowed skew, until that holds.
    """

    def __init__(self) -> None:
        torsion = bytes.fromhex(
            [c for c in VECTORS["ed25519_verification"]["cases"] if c["name"] == "small-order-A-1"][0]["public_key_hex"]
        )
        self._scalar = crypto_core_ed25519_scalar_reduce(os.urandom(64))
        self._public = crypto_core_ed25519_add(crypto_scalarmult_ed25519_base_noclamp(self._scalar), torsion)
        self.did_key = did_from_public_key(self._public)

    @property
    def public_key(self) -> bytes:
        return self._public

    def sign_timed(self, payload) -> tuple[str, str]:
        """(timestamp, signature) over ``payload(timestamp)``, for a timestamp whose challenge suits this key."""
        timestamp, _, signature = self._sign_with_divisible_challenge(payload)
        return timestamp, signature

    def signed_headers(self, *, domain: str, operation: str, **extra) -> dict:
        """Legacy DIDKey headers over {domain, operation, timestamp, **extra}."""

        def payload(timestamp: str) -> bytes:
            return canonical_json_bytes({"domain": domain, "operation": operation, "timestamp": timestamp, **extra})

        timestamp, _, signature = self._sign_with_divisible_challenge(payload)
        return {"Authorization": f"DIDKey {self.did_key} {signature}", "X-AWEB-Timestamp": timestamp}

    def covering_headers(self, *, method: str, path: str, body: bytes, domain: str, operation: str) -> dict:
        """Covering-v2 headers signed by this key."""

        def payload(timestamp: str) -> bytes:
            return canonical_json_bytes({
                "v": 2, "type": REQUEST_TYPE, "aud": ORIGIN, "method": method, "path": path,
                "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
                "domain": domain, "operation": operation,
            })

        timestamp, raw, signature = self._sign_with_divisible_challenge(payload)
        return {
            "Authorization": f"DIDKey {self.did_key} {signature}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
            "Content-Type": "application/json",
        }

    def _sign_with_divisible_challenge(self, payload) -> tuple[str, bytes, str]:
        base = datetime.now(timezone.utc).replace(microsecond=0)
        for offset in range(0, 240):
            timestamp = (base - timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
            raw = payload(timestamp)
            nonce = crypto_core_ed25519_scalar_reduce(os.urandom(64))
            commitment = crypto_scalarmult_ed25519_base_noclamp(nonce)
            challenge = crypto_core_ed25519_scalar_reduce(hashlib.sha512(commitment + self._public + raw).digest())
            if int.from_bytes(challenge, "little") % 8:
                continue
            response = crypto_core_ed25519_scalar_add(nonce, crypto_core_ed25519_scalar_mul(challenge, self._scalar))
            return timestamp, raw, base64.b64encode(commitment + response).rstrip(b"=").decode()
        raise AssertionError("no timestamp gave a challenge divisible by 8")


class Tree:
    """One registry, its manual clock and the vector identities enrolled in it."""

    def __init__(self, client, clock):
        self.client = client
        self.clock = clock
        client.app.state.awid_public_origins = (ORIGIN,)

    def dns(self, controller: str | None, *, inherited: bool = False, domain: str = DOMAIN) -> None:
        """Answer DNS for ``domain`` with ``controller``'s key, or fail when it is None."""

        async def _verify(queried: str) -> DomainAuthority:
            if queried != domain or controller is None:
                raise DnsVerificationError(f"DNS lookup failed for _awid.{queried}")
            return DomainAuthority(
                controller_did=did_key(controller), registry_url=ORIGIN, dns_name=f"_awid.{queried}",
                inherited=inherited,
            )

        self.client.app.dependency_overrides[get_domain_verifier] = lambda: _verify

    def exact_dns(self, controller: str, domain: str = DOMAIN) -> None:
        self.dns(controller, domain=domain)

    async def register_namespace(self, controller: str = "root", *, domain: str = DOMAIN, headers=None):
        """POST /v1/namespaces signed by ``controller``; DNS answers as last set."""
        signed = build_signed_headers(seed(controller), did_key(controller), domain=domain, operation="register")
        return await self.client.post("/v1/namespaces", json={"domain": domain}, headers={**signed, **(headers or {})})

    async def root(self, *, controller: str = "root", domain: str = DOMAIN) -> None:
        self.exact_dns(controller, domain)
        resp = await self.register_namespace(controller, domain=domain)
        assert resp.status_code == 200, resp.text

    async def replace_controller(self, new_controller: str, *, domain: str = DOMAIN, headers=None):
        """PUT /v1/namespaces/{domain}, the new-key-only recovery path."""
        signed = build_signed_headers(
            seed(new_controller), did_key(new_controller), domain=domain,
            operation="rotate_controller", new_controller_did=did_key(new_controller),
        )
        return await self.client.put(
            f"/v1/namespaces/{domain}", json={"new_controller_did": did_key(new_controller)},
            headers={**signed, **(headers or {})},
        )

    async def replace_root(self, new_controller: str, domain: str = DOMAIN) -> None:
        self.exact_dns(new_controller, domain)
        resp = await self.replace_controller(new_controller, domain=domain)
        assert resp.status_code == 200, resp.text

    async def delete_namespace(self, controller: str = "root", *, domain: str = DOMAIN):
        headers = build_signed_headers(seed(controller), did_key(controller), domain=domain, operation="delete_namespace")
        return await self.client.request("DELETE", f"/v1/namespaces/{domain}", headers=headers)

    async def reverify(self, *, domain: str = DOMAIN):
        return await self.client.post(f"/v1/namespaces/{domain}/reverify")

    async def did(self, key_name: str) -> None:
        await register_identity(self.client, seed(key_name), did_key(key_name))

    async def vector_did(self, key_name: str) -> None:
        """Register ``key_name``'s did:aw with its frozen log entry, witnessed at that entry's time."""
        entry = did_registration_entry(key_name)
        fields = ("did_aw", "new_did_key", "operation", "previous_did_key", "prev_entry_hash", "seq",
                  "state_hash", "authorized_by", "timestamp")
        body = {"did_aw": did_aw(key_name), **{field: entry[field] for field in fields[1:]}, "proof": entry["signature"]}
        signed_at = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        self.clock.now = signed_at
        real_now = dns_auth._utc_now
        dns_auth._utc_now = lambda: signed_at
        try:
            resp = await self.client.post("/v1/did", json=body)
        finally:
            dns_auth._utc_now = real_now
        assert resp.status_code == 200, resp.text

    async def rotate_did(self, key_name: str, new_key_name: str) -> None:
        resp = await request_rotation(
            self.client, seed(key_name), did_aw(key_name), did_key(key_name), did_key(new_key_name),
        )
        assert resp.status_code == 200, resp.text

    async def register(
        self, chain: list[dict], *, signer: str | None = None, expected_head: str | None = None,
        invitation_id: str | None = None, when: datetime | None = None, header_chain: list[dict] | None = None,
    ):
        """POST the leaf of ``chain`` with ``chain`` as its supporting header."""
        if when is not None:
            self.clock.now = when
        leaf = chain[-1]["certificate"]
        signer = signer or key_name_for(leaf["id"])
        body = json.dumps(
            {"certificate": chain[-1], "expected_head": expected_head, "invitation_id": invitation_id},
            separators=(",", ":"),
        ).encode()
        headers = covering_headers(
            signer, method="POST", path=REGISTER_PATH, body=body,
            domain=leaf["domain"], operation="register_id_certificate",
        )
        headers["X-AWID-ID-Chain"] = chain_header(header_chain if header_chain is not None else chain)
        return await self.client.post(REGISTER_PATH, content=body, headers=headers)

    async def revoke(
        self, actor: str, subject: str, *, expected_head: str | None, effective_from: str | None = None,
        when: datetime | None = None,
    ):
        """POST a revocation of ``subject`` signed by ``actor``'s current key."""
        if when is not None:
            self.clock.now = when
        body = json.dumps(
            {"domain": DOMAIN, "id": did_aw(subject), "expected_head": expected_head, "effective_from": effective_from},
            separators=(",", ":"),
        ).encode()
        headers = covering_headers(
            actor, method="POST", path=REVOKE_PATH, body=body, domain=DOMAIN, operation="revoke_id_certificate",
        )
        return await self.client.post(REVOKE_PATH, content=body, headers=headers)

    async def enroll(self, *names: str, when: datetime | None = None) -> None:
        """Register vector certificates in order, each under the chain before it."""
        chain: list[dict] = []
        for name in names:
            signed = certificate(name)
            chain = self._ancestry(chain, signed)
            resp = await self.register(chain, when=when)
            assert resp.status_code == 200, resp.text

    @staticmethod
    def _ancestry(chain: list[dict], signed: dict) -> list[dict]:
        parent = signed["certificate"]["parent"]
        if parent["kind"] == "namespace":
            return [signed]
        for index, link in enumerate(chain):
            if link["certificate"]["id"] == parent["id"]:
                return chain[: index + 1] + [signed]
        raise AssertionError(f"enroll {parent['id']} before its child")
