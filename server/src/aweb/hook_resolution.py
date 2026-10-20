"""Reading a team's hook bindings for resolution (design app-team-server-api.md §4).

A binding is active by its state alone: activated, unrevoked and of the
installation's current generation, including while it pads to its
``active_from``. The caller compares ``active_from`` with an event's time.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from aweb.hook_bindings import BINDING_COLUMNS, PRODUCTION, REGISTRATION, HookBinding, binding_from_row

# The key purposes a production's keys are listed for: the event signature and
# the delivery credential. Any other purpose is never listed.
HOOK_KEY_PURPOSES = ("hook-delivery", "hook-event")


@dataclass(frozen=True)
class HookKey:
    kid: str
    did_key: str
    purposes: tuple[str, ...]


@dataclass(frozen=True)
class HookSelector:
    catalog_id: str
    catalog_version: int
    hook: str


def complement(kind: str) -> str:
    """The binding kind that authorizes reading bindings of ``kind``."""
    return PRODUCTION if kind == REGISTRATION else REGISTRATION


async def holds_active_binding(
    db, *, team_id: str, app_id: str, digest: str, kind: str, selector: HookSelector
) -> bool:
    """Whether the app, installed at ``digest``, holds an active binding of ``kind`` for the hook."""
    row = await db.fetch_one(
        """
        SELECT 1 FROM {{tables.app_hook_bindings}}
        WHERE team_id = $1 AND app_id = $2 AND digest = $3 AND kind = $4
          AND catalog_id = $5 AND catalog_version = $6 AND hook = $7 AND state = 'active'
        """,
        team_id,
        app_id,
        digest,
        kind,
        selector.catalog_id,
        selector.catalog_version,
        selector.hook,
    )
    return row is not None


async def active_bindings(db, *, team_id: str, kind: str, selector: HookSelector) -> list[HookBinding]:
    """The team's active bindings of ``kind`` for the hook, oldest activation first."""
    rows = await db.fetch_all(
        f"""
        SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}
        WHERE team_id = $1 AND kind = $2 AND catalog_id = $3 AND catalog_version = $4 AND hook = $5
          AND state = 'active'
        ORDER BY activated_at, binding_id
        """,
        team_id,
        kind,
        selector.catalog_id,
        selector.catalog_version,
        selector.hook,
    )
    return [binding_from_row(row) for row in rows]


async def hook_keys(db, binding: HookBinding) -> list[HookKey]:
    """A production's unrevoked keys of its own installed digest that declare a hook purpose."""
    rows = await db.fetch_all(
        """
        SELECT key_id, did_key, purposes FROM {{tables.team_app_keys}}
        WHERE team_id = $1 AND app_id = $2 AND origin = $3 AND digest = $4
          AND revoked_at IS NULL AND purposes && $5::TEXT[]
        ORDER BY key_id
        """,
        binding.team_id,
        binding.app_id,
        binding.origin,
        binding.digest,
        list(HOOK_KEY_PURPOSES),
    )
    return [
        HookKey(kid=row["key_id"], did_key=row["did_key"], purposes=tuple(sorted(row["purposes"])))
        for row in rows
    ]


async def own_bindings(
    db,
    *,
    team_id: str,
    app_id: str,
    origin: str,
    binding_id: UUID | None = None,
    selector: HookSelector | None = None,
) -> list[HookBinding]:
    """The app's own bindings in the team from its installed origin, in every
    state and across that origin's digests, by id or by hook. Bindings of an
    earlier origin under the same app id are another publisher's."""
    if (binding_id is None) == (selector is None):
        raise ValueError("select own bindings by exactly one of binding_id or hook")
    if binding_id is not None:
        rows = await db.fetch_all(
            f"""
            SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}
            WHERE team_id = $1 AND app_id = $2 AND origin = $3 AND binding_id = $4
            """,
            team_id,
            app_id,
            origin,
            binding_id,
        )
    else:
        assert selector is not None
        rows = await db.fetch_all(
            f"""
            SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}
            WHERE team_id = $1 AND app_id = $2 AND origin = $3
              AND catalog_id = $4 AND catalog_version = $5 AND hook = $6
            ORDER BY created_at, binding_id
            """,
            team_id,
            app_id,
            origin,
            selector.catalog_id,
            selector.catalog_version,
            selector.hook,
        )
    return [binding_from_row(row) for row in rows]
