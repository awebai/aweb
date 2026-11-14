"""Frozen-request display templates exported by the operation definition.

Sources are JSON pointers into the frozen request, never live lookups. New
resolved names require the separately negotiated wire description; this data
does not add members to an existing prepared request.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationDisplay:
    title: str
    consequences: tuple[str, ...]
    names: tuple[tuple[str, str], ...]
    technical: tuple[tuple[str, str], ...]
    refusals: tuple[tuple[str, str], ...]
    responsibility_statement: str | None = None

    def fields(self):
        return {"title": self.title,
            "consequences": ([self.responsibility_statement] if self.responsibility_statement else []) + list(self.consequences),
            "names": dict(self.names), "technical": dict(self.technical), "refusals": dict(self.refusals)}
