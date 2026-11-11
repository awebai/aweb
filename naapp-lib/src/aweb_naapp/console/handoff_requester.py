"""The direct-child requester of an app session start (handoff-wire 1a).

A session start may be signed by an agent Q whose freshly verified ID chain
has the holder H as its DIRECT parent. That admits Q to prepare this one
session handoff only: never H's login, holding, membership or approval. The
holder's own app-RP login and explicit Allow still decide the session.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from awid.id_certificates import IDCertificateError, decode_id_chain_header, verify_id_chain
from fastapi import HTTPException, Request

from aweb_naapp.runtime.team_auth import Principal

CHAIN_HEADER = "X-AWID-ID-Chain"


@dataclass(frozen=True)
class Requester:
    """The agent that prepared a start for its parent; display and audit only."""

    id: str
    address: str | None
    key_fingerprint: str

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "address": self.address, "key_fingerprint": self.key_fingerprint}


RequesterParent = Callable[[Request, Principal], Awaitable[str | None]]


def key_fingerprint(did_key: str) -> str:
    """The first 16 hex characters of SHA-256(did:key), in four groups."""
    digest = hashlib.sha256(did_key.encode()).hexdigest()[:16]
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


def requester_parent(registry: Any) -> RequesterParent:
    """Verify the signer's chain from current evidence and return its direct human parent.

    ``registry`` is the runtime's registry client; its ``id_chain_evidence``
    serves status evidence no older than 60 seconds or refreshes it. Returns
    None when the chain is absent, invalid, or the signer is not an agent
    whose own certificate's issuer is a human. Evidence that cannot be read
    refuses ``503 principal_status_unavailable``; nothing falls back.
    """

    async def parent(request: Request, signer: Principal) -> str | None:
        values = request.headers.getlist(CHAIN_HEADER)
        if len(values) != 1 or not signer.did_aw:
            return None
        try:
            bundle = decode_id_chain_header(values[0])
            certificates = bundle["certificates"]
            leaf = certificates[-1]["certificate"]
            issuer = certificates[-2]["certificate"]
        except (IDCertificateError, KeyError, IndexError, TypeError, ValueError):
            return None
        subject = {"id": signer.did_aw, "did_key": signer.did_key}
        domain = leaf.get("domain")
        if not isinstance(domain, str):
            return None
        evidence = await registry.id_chain_evidence(bundle, subject, domain=domain)
        result = verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)
        if result.get("outcome") == "unavailable":
            raise HTTPException(503, "principal_status_unavailable")
        if result.get("identity_valid") is not True or result.get("kind") != "agent":
            return None
        edge = leaf.get("parent") or {}
        if edge.get("kind") != "identity" or issuer.get("kind") != "human":
            return None
        if issuer.get("id") != edge.get("id"):
            return None
        return edge["id"]

    return parent
