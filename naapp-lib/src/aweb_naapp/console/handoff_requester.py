"""The direct-child requester of an app session start (handoff-wire 1a).

A session start may be signed by an agent Q whose freshly verified ID chain
has the holder H as its DIRECT parent. That admits Q to prepare this one
session handoff only: never H's login, holding, membership or approval. The
holder's own app-RP login and explicit Allow still decide the session.
"""

from __future__ import annotations

import hashlib
import math
import time
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


@dataclass(frozen=True)
class RequesterEvidence:
    """The verified direct parent of a start's signer, valid until the original
    evidence's 60-second freshness bound (monotonic ns). It is rechecked at the
    start's final effect, never renewed by a lock wait."""

    parent: str
    fresh_until: int

    def require_fresh(self) -> None:
        if time.monotonic_ns() > self.fresh_until:
            raise HTTPException(503, "principal_status_unavailable")


RequesterParent = Callable[[Request, Principal], Awaitable[RequesterEvidence | None]]

FRESHNESS_SECONDS = 60


def key_fingerprint(did_key: str) -> str:
    """The first 16 hex characters of SHA-256(did:key), in four groups."""
    digest = hashlib.sha256(did_key.encode()).hexdigest()[:16]
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


def requester_parent(registry: Any) -> RequesterParent:
    """Verify the signer's chain from current evidence and return its direct human
    parent, with the original evidence deadline.

    ``registry`` is the runtime's registry client; its ``id_chain_evidence``
    serves status evidence no older than 60 seconds or refreshes it. Returns
    None when the chain is absent, invalid, or the signer is not an agent
    whose own certificate's issuer is a human. Evidence that cannot be read
    refuses ``503 principal_status_unavailable``; nothing falls back.
    """

    async def parent(request: Request, signer: Principal) -> RequesterEvidence | None:
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
        started = time.monotonic_ns()
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
        age = evidence.age_seconds if evidence.age_seconds is not None else FRESHNESS_SECONDS
        fresh_until = started + math.floor((FRESHNESS_SECONDS - age) * 1_000_000_000)
        return RequesterEvidence(edge["id"], fresh_until)

    return parent
