#!/usr/bin/env python3
"""The read-back status engine's row model (aben, design section 8).

Four states that no path collapses: a row is OBSERVED-PRESENT only on
identity evidence, UNPROVEN never renders present, unavailability is
never absence and never success, and the monitor's typed
remote-completion record cannot construct a row at all - a workflow
conclusion is never publication status. Status language claims immutable
public identity with a source anchor and never claims reproduction.
"""

from __future__ import annotations

import dataclasses

STATES = (
    "observed-present",
    "observed-absent",
    "conflict-unproven",
    "unavailable",
)


class StatusError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class RemoteCompletion:
    """The monitor's whole vocabulary: which workflow, at which SHA, with
    which conclusion. Deliberately carries no artifact identity."""

    workflow: str
    run_sha: str
    conclusion: str


@dataclasses.dataclass(frozen=True)
class Row:
    fact: str
    state: str
    evidence: str

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise StatusError(f"{self.fact}: unknown row state {self.state!r}")
        if not self.fact or not self.evidence:
            raise StatusError("a row needs its fact and its evidence")

    @staticmethod
    def from_monitor(record: RemoteCompletion) -> "Row":
        raise StatusError(
            "a workflow conclusion is capability evidence, not publication "
            "status - rows come from registry read-backs only"
        )

    def present(self) -> bool:
        return self.state == "observed-present"

    def absent(self) -> bool:
        return self.state == "observed-absent"

    def render(self) -> str:
        if self.state == "observed-present":
            return (
                f"PRESENT {self.fact}: registry artifact present with "
                f"immutable public identity and source anchor ({self.evidence})"
            )
        if self.state == "observed-absent":
            return f"ABSENT {self.fact} ({self.evidence})"
        if self.state == "conflict-unproven":
            return f"CONFLICT/UNPROVEN {self.fact} ({self.evidence})"
        return f"UNAVAILABLE {self.fact} ({self.evidence})"


def done(rows) -> bool:
    """DONE is the complete intended world: every row observed-present.
    Absence, conflict, or unavailability anywhere is not DONE."""

    rows = list(rows)
    return bool(rows) and all(row.present() for row in rows)
