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
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey

from awid.dns_verify import DomainAuthority
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


def key_name_for(identity: str) -> str:
    [name] = [name for name, key in KEYS.items() if identity in (key["did_aw"], key["did_key"])]
    return name


def sign(fields: dict, signer: str) -> dict:
    """A certificate the test itself issues with a synthetic vector key."""
    signature = SigningKey(seed(signer)).sign(id_certificate_signing_bytes(fields)).signature
    return {"certificate": fields, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}


def covering_headers(signer: str, *, method: str, path: str, body: bytes, domain: str, operation: str) -> dict:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {
        "v": 2, "type": REQUEST_TYPE, "aud": ORIGIN, "method": method, "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
        "domain": domain, "operation": operation,
    }
    raw = canonical_json_bytes(payload)
    return {
        "Authorization": f"DIDKey {did_key(signer)} {sign_message(seed(signer), raw)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "Content-Type": "application/json",
    }


def chain_header(chain: list[dict]) -> str:
    return encode_id_chain_header({"v": 1, "type": "aweb.id-chain", "certificates": chain})


class Tree:
    """One registry, its manual clock and the vector identities enrolled in it."""

    def __init__(self, client, clock):
        self.client = client
        self.clock = clock
        client.app.state.awid_public_origins = (ORIGIN,)

    def exact_dns(self, controller: str, domain: str = DOMAIN) -> None:
        async def _verify(queried: str) -> DomainAuthority:
            assert queried == domain
            return DomainAuthority(
                controller_did=did_key(controller), registry_url=ORIGIN, dns_name=f"_awid.{queried}",
            )

        self.client.app.dependency_overrides[get_domain_verifier] = lambda: _verify

    async def root(self, *, controller: str = "root", domain: str = DOMAIN) -> None:
        self.exact_dns(controller, domain)
        headers = build_signed_headers(seed(controller), did_key(controller), domain=domain, operation="register")
        resp = await self.client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
        assert resp.status_code == 200, resp.text

    async def rotate_root(self, new_controller: str, domain: str = DOMAIN) -> None:
        self.exact_dns(new_controller, domain)
        headers = build_signed_headers(
            seed(new_controller), did_key(new_controller), domain=domain,
            operation="rotate_controller", new_controller_did=did_key(new_controller),
        )
        resp = await self.client.put(
            f"/v1/namespaces/{domain}", json={"new_controller_did": did_key(new_controller)}, headers=headers,
        )
        assert resp.status_code == 200, resp.text

    async def did(self, key_name: str) -> None:
        await register_identity(self.client, seed(key_name), did_key(key_name))

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
