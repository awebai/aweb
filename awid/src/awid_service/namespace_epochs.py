"""Namespace controller epochs (docs/id-certificates.md "Namespace continuity and replacement").

Every root key change appends to one witnessed history per domain instead of
overwriting the only evidence of an old root key. An epoch is opened only by
an explicit act with exact DNS or verified parent authorization: first registration,
re-registration after deletion, a key change through the new-key recovery
PUT (all ``replaced``), or a rotation signed by the previous key
(``rotated``). Observations of DNS never open, replace or retire an epoch.
Callers hold the namespace row lock (or create the row) before writing.
"""

from __future__ import annotations

from awid.dns_verify import DomainAuthority
from awid.id_certificates import namespace_authority_valid

from awid_service.id_tree_clock import Clock, serialization_time

ROTATED = "rotated"
REPLACED = "replaced"


def is_exact(authority: DomainAuthority | None) -> bool:
    """Whether DNS proved the domain itself rather than an ancestor."""
    return authority is not None and not authority.inherited


def delegation_of(namespace) -> dict | None:
    """The persisted parent authorization, bound to the current child key."""
    if namespace is None or namespace.get("parent_domain") is None or namespace.get("parent_controller_key") is None:
        return None
    return {"parent_domain": namespace["parent_domain"],
            "parent_controller_key": namespace["parent_controller_key"],
            "controller_key": namespace["controller_did"]}


def authority_evidence(domain: str, authority: DomainAuthority | None) -> dict:
    return {"domain": domain, "dns_name": authority.dns_name if authority else None,
            "inherited": authority.inherited if authority else False,
            "controller_key": authority.controller_did if authority else None}


def proves_root(authority: DomainAuthority | None, did_key: str, *, domain: str | None = None, namespace=None) -> bool:
    """Whether found DNS and the parent-authorized record establish this root."""
    if authority is None:
        return False
    domain = domain or authority.dns_name.removeprefix("_awid.")
    return namespace_authority_valid(domain, authority_evidence(domain, authority), did_key, delegation_of(namespace))


async def record_delegation(tx, *, domain: str, parent) -> None:
    """Only callers that verified the existing parent proof may record it."""
    await tx.execute(
        """UPDATE {{tables.dns_namespaces}}
           SET parent_domain = $2, parent_controller_key = $3
           WHERE domain = $1 AND deleted_at IS NULL""",
        domain, parent["domain"], parent["controller_did"],
    )


async def advance_delegated_children(tx, *, domain: str, controller_key: str) -> None:
    """A signed parent controller change preserves its direct delegations atomically."""
    await tx.execute(
        """UPDATE {{tables.dns_namespaces}}
           SET parent_controller_key = $2
           WHERE parent_domain = $1 AND deleted_at IS NULL""",
        domain, controller_key,
    )


async def open_epoch(tx, *, domain: str, did_key: str, continuity: str, clock: Clock) -> None:
    """Retire the open epoch, if any, and open its successor at one witness time."""
    current = await open_epoch_of(tx, domain, for_update=True)
    at = serialization_time(clock, await latest_domain_event(tx, domain))
    if current is not None:
        await _retire(tx, domain, current["seq"], at)
    await tx.execute(
        """
        INSERT INTO {{tables.id_namespace_epochs}}
            (domain, seq, did_key, continuity, registered_at, retired_at)
        SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, $3, $4, NULL
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1
        """,
        domain,
        did_key,
        continuity,
        at,
    )


async def has_epoch_history(tx, domain: str) -> bool:
    return await tx.fetch_value(
        "SELECT EXISTS (SELECT 1 FROM {{tables.id_namespace_epochs}} WHERE domain = $1)", domain,
    )


async def retire_namespace_controller(tx, *, domain: str, clock: Clock) -> None:
    current = await open_epoch_of(tx, domain, for_update=True)
    if current is None:
        return
    at = serialization_time(clock, await latest_domain_event(tx, domain))
    await _retire(tx, domain, current["seq"], at)


async def open_epoch_of(tx, domain: str, *, for_update: bool = False):
    return await tx.fetch_one(
        f"""
        SELECT seq, did_key, continuity, registered_at
        FROM {{{{tables.id_namespace_epochs}}}}
        WHERE domain = $1 AND retired_at IS NULL
        {"FOR UPDATE" if for_update else ""}
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


async def latest_domain_event(tx, domain: str):
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
