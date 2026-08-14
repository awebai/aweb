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
    card_rows, result: rn.NormalizerResult, *, expected_sources=None
) -> list[rn.Stop]:
    """Stops describing every difference the allowlist does not permit.

    A moving row observed complete at the card version is progress ONLY
    when its fresh anchor identity equals the source the card names for
    that artifact (expected_sources, derived from the card's SHAs) -
    same-version completion from any other source is the named
    mismatch, and a completion whose expected source cannot be derived
    yet is unproven, never accepted. The comparison is two-way: fresh
    artifacts the card does not carry, and a fresh wish for new patches,
    are drift.
    """

    expected_sources = expected_sources or {}
    stops: list[rn.Stop] = list(result.stops)
    card_names = {row.name for row in card_rows}
    for name in sorted(set(result.artifacts) - card_names):
        stops.append(rn.Stop("card-world-extra-artifact", name))
    if result.patches or getattr(result, "floor_patches", ()):
        stops.append(rn.Stop("card-world-patch-drift"))
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
        if fresh.disposition == "unmoved":
            fresh_anchor = fresh.previous_complete_anchor
            if fresh_anchor is None or fresh_anchor[1] is None:
                # Correct on its own terms, not because no construction
                # path produces this: an unmoved row whose fresh anchor
                # is missing or identityless is anchorless, named.
                stops.append(rn.Stop("card-world-anchor-missing", row.name))
                continue
            if row.disposition in ("moving", "moving-with-recovery"):
                # A completion: this train (or a legitimate parallel
                # attempt of it) published the card's version, so the
                # served bytes must bind to the card's OWN source.
                if row.name not in (expected_sources or {}) or (
                    expected_sources.get(row.name) is None
                ):
                    stops.append(
                        rn.Stop("card-world-source-unproven", row.name)
                    )
                    continue
                if fresh_anchor[1] != expected_sources[row.name]:
                    stops.append(
                        rn.Stop("card-world-source-mismatch", row.name)
                    )
                    continue
            if (
                row.previous_complete_anchor is not None
                and row.previous_complete_anchor[1] is not None
                and row.previous_complete_anchor[1] != fresh_anchor[1]
                and row.disposition == "unmoved"
            ):
                stops.append(rn.Stop("card-world-anchor-drift", row.name))
    return stops
