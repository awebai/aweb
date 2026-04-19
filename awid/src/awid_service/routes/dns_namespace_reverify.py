from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from awid.dns_verify import DnsVerificationError, DomainVerifier

logger = logging.getLogger(__name__)

_RESERVED_LOCAL_DOMAINS = {"local"}


@dataclass(frozen=True)
class NamespaceReverifyResult:
    row: Any
    old_controller_did: str | None
    new_controller_did: str | None
    rotated: bool


def is_reserved_local_domain(domain: str) -> bool:
    return domain in _RESERVED_LOCAL_DOMAINS


async def reverify_namespace_row(
    db,
    ns_row,
    *,
    domain: str,
    verify_domain: DomainVerifier,
    allow_local_bypass: bool,
    dns_failure_status: int,
    dns_failure_detail: str | None = None,
) -> NamespaceReverifyResult:
    if is_reserved_local_domain(domain):
        if allow_local_bypass:
            old_controller_did = ns_row["controller_did"]
            return NamespaceReverifyResult(
                row=ns_row,
                old_controller_did=old_controller_did,
                new_controller_did=old_controller_did,
                rotated=False,
            )
        raise HTTPException(status_code=400, detail="local namespaces have no DNS to reverify")

    try:
        dns_authority = await verify_domain(domain)
    except DnsVerificationError as exc:
        raise HTTPException(
            status_code=dns_failure_status,
            detail=dns_failure_detail or str(exc),
        ) from exc

    old_controller_did = ns_row["controller_did"]
    # When the DNS record comes from a parent domain, the controller_did
    # belongs to the parent — not this namespace.  Refresh the timestamp
    # (the domain tree is still alive) but do not rotate the controller.
    if dns_authority.inherited:
        new_controller_did = old_controller_did
    else:
        new_controller_did = dns_authority.controller_did
    now = datetime.now(timezone.utc)

    if new_controller_did == old_controller_did:
        row = await db.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET verification_status = 'verified',
                last_verified_at = $2
            WHERE namespace_id = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      last_verified_at, created_at
            """,
            ns_row["namespace_id"],
            now,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        return NamespaceReverifyResult(
            row=row,
            old_controller_did=old_controller_did,
            new_controller_did=new_controller_did,
            rotated=False,
        )

    row = await db.fetch_one(
        """
        UPDATE {{tables.dns_namespaces}}
        SET controller_did = $2,
            verification_status = 'verified',
            last_verified_at = $3
        WHERE namespace_id = $1 AND deleted_at IS NULL
        RETURNING namespace_id, domain, controller_did, verification_status,
                  last_verified_at, created_at
        """,
        ns_row["namespace_id"],
        new_controller_did,
        now,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")

    logger.warning(
        "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
        domain,
        old_controller_did,
        new_controller_did,
    )
    return NamespaceReverifyResult(
        row=row,
        old_controller_did=old_controller_did,
        new_controller_did=new_controller_did,
        rotated=True,
    )
