#!/usr/bin/env python3
"""Continue-start card-versus-world verification (aben, design section 7).

The same normalizer runs in no-apply mode over the exact card SHAs with
fresh observations; this module compares its complete result to the
card's projection. Byte-equal everywhere except the monotone progress
transitions; every other difference stops in the reconciler's
vocabulary, before the first irreversible edge.
"""

from __future__ import annotations

import dataclasses

import release_normalizer as rn

# The progress allowlist: (card disposition) -> permitted fresh
# dispositions beyond identity. Everything else is drift.
_PROGRESS = {
    "moving": {"moving", "moving-with-recovery", "unmoved"},
    "moving-with-recovery": {"moving-with-recovery", "unmoved"},
    "unmoved": {"unmoved"},
}


@dataclasses.dataclass(frozen=True)
class CardRow:
    """One card artifact row's projection for comparison."""

    name: str
    version: str
    disposition: str
    previous_complete_anchor: tuple[str, str | None] | None


def verify_card_against_world(
    card_rows, result: rn.NormalizerResult
) -> list[rn.Stop]:
    """Stops describing every difference the allowlist does not permit.

    A moving row observed complete at the card version is progress (an
    earlier attempt or parallel publisher finished it); recoverable is
    progress toward complete; any version difference, disposition
    regression, or anchor identity change is drift, named.
    """

    stops: list[rn.Stop] = list(result.stops)
    for row in card_rows:
        fresh = result.artifacts.get(row.name)
        if fresh is None:
            stops.append(rn.Stop("card-world-artifact-missing", row.name))
            continue
        if fresh.version != row.version:
            stops.append(rn.Stop("card-world-version-drift", row.name))
            continue
        if fresh.disposition not in _PROGRESS[row.disposition]:
            stops.append(rn.Stop("card-world-disposition-drift", row.name))
            continue
        if (
            row.disposition == "unmoved"
            and fresh.disposition == "unmoved"
            and row.previous_complete_anchor is not None
            and fresh.previous_complete_anchor is not None
            and row.previous_complete_anchor[1] is not None
            and fresh.previous_complete_anchor[1] is not None
            and row.previous_complete_anchor[1]
            != fresh.previous_complete_anchor[1]
        ):
            stops.append(rn.Stop("card-world-anchor-drift", row.name))
    return stops
