"""Namespace controller epochs (docs/id-certificates.md §3 "Key rotation").

Every controller change appends to one history per domain instead of
overwriting the only evidence of an old root key. Only an epoch proven by the
exact ``_awid.<domain>`` TXT record establishes the domain's identity-tree
root; the other ways AWID accepts a controller are recorded but never exact.
Callers hold the namespace row lock (or create the row) before recording.
"""

from __future__ import annotations

from awid.dns_verify import DomainAuthority

from awid_service.id_tree_clock import Clock, serialization_time

DNS_EXACT = "dns_exact"
DNS_INHERITED = "dns_inherited"
PARENT_AUTHORIZATION = "parent_authorization"
UNVERIFIED = "unverified"


def dns_establishment(authority: DomainAuthority) -> str:
    return DNS_INHERITED if authority.inherited else DNS_EXACT


async def record_namespace_controller(
    tx, *, domain: str, did_key: str, established_by: str, clock: Clock,
) -> None:
    """Open an epoch for ``did_key`` unless the open one already covers it.

    A re-assertion of the open key keeps its epoch, except that exact DNS
    proof of a key held on weaker evidence opens a new, exact epoch.
    """
    current = await _lock_open_epoch(tx, domain)
    if (
        current is not None
        and current["did_key"] == did_key
        and (current["established_by"] == DNS_EXACT or established_by != DNS_EXACT)
    ):
        return
    at = serialization_time(clock, await _latest_domain_event(tx, domain))
    if current is not None:
        await _retire(tx, domain, current["seq"], at)
    await tx.execute(
        """
        INSERT INTO {{tables.id_namespace_epochs}}
            (domain, seq, did_key, established_by, registered_at, retired_at)
        SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, $3, $4, NULL
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1
        """,
        domain,
        did_key,
        established_by,
        at,
    )


async def retire_namespace_controller(tx, *, domain: str, clock: Clock) -> None:
    current = await _lock_open_epoch(tx, domain)
    if current is None:
        return
    at = serialization_time(clock, await _latest_domain_event(tx, domain))
    await _retire(tx, domain, current["seq"], at)


async def _lock_open_epoch(tx, domain: str):
    return await tx.fetch_one(
        """
        SELECT seq, did_key, established_by
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1 AND retired_at IS NULL
        FOR UPDATE
        """,
        domain,
    )


async def _retire(tx, domain: str, seq: int, at) -> None:
    await tx.execute(
        """
        UPDATE {{tables.id_namespace_epochs}}
        SET retired_at = $3
        WHERE domain = $1 AND seq = $2
        """,
        domain,
        seq,
        at,
    )


async def _latest_domain_event(tx, domain: str):
    """The latest identity-tree witness time in ``domain``.

    A root key change conflicts with every registration and revocation the
    old key may have authorized, so its time follows all of them.
    """
    return await tx.fetch_value(
        """
        SELECT GREATEST(
            (SELECT MAX(GREATEST(registered_at, COALESCE(retired_at, registered_at)))
             FROM {{tables.id_namespace_epochs}} WHERE domain = $1),
            (SELECT MAX(GREATEST(registered_at, COALESCE(superseded_at, registered_at)))
             FROM {{tables.id_certificates}} WHERE domain = $1),
            (SELECT MAX(revoked_at) FROM {{tables.id_identities}} WHERE domain = $1)
        )
        """,
        domain,
    )
