"""Checked-in skew journey registry: the child registration seam.

The G5 matrix runner routes each runtime-contract edge's cells to the
harness registered for the edge's exact journey string. The children
(aweb-abbe.7.1 CLI-server, .7.2 channel/Pi-server, .7.3 federation
server-server, .7.4 persisted-state) register here and implement ONLY the
small invocation contract - runner semantics never change:

    register("<journey string from components.toml>", factory)

where factory() returns an object with

    run(cell) -> None      green
    run(cell) -> raise     red (any exception; the runner wraps it with
                           the cell identity and fails the release before
                           any continuation dispatch)

A cell is a release_driver.SkewCell: frozen, carrying the edge identity,
journey, request direction, per-side kind (candidate | published-latest |
published-floor | published), and per-side identity - candidate sides
include the exact staged digest set AND the structured lane reference for
retrieving the exact G1-staged bytes; published sides carry the measured
version to download from the registry.

An edge whose journey has no registration is REFUSED by the release path
(never silently skipped); a duplicate registration refuses here.
"""

from __future__ import annotations

REGISTRY: dict[str, object] = {}


def register(journey: str, factory) -> None:
    if not journey or not isinstance(journey, str):
        raise ValueError(f"journey must be a nonempty string, got {journey!r}")
    if journey in REGISTRY:
        import release_driver

        raise release_driver.ReceiptError(
            f"skew journey {journey!r} is already registered; one harness "
            "owns each journey"
        )
    REGISTRY[journey] = factory
