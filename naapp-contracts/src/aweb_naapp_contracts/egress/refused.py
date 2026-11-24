"""The one refusal the egress guard raises."""

from __future__ import annotations


class EgressRefused(Exception):
    """The guard refused a request before sending any byte of it.

    ``code`` is a value of the hook catalog's ``refusal_code`` enum, which
    callers record. ``rule`` names the clause of the egress URL contract (its
    conformance vector in ``docs/vectors``) that fired. The message is for
    operators and never carries a credential.
    """

    def __init__(self, code: str, rule: str, detail: str = "") -> None:
        super().__init__(f"{code} ({rule}): {detail}" if detail else f"{code} ({rule})")
        self.code = code
        self.rule = rule
        self.detail = detail
