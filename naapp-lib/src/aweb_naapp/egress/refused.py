"""The one refusal the egress guard raises."""

from __future__ import annotations


class EgressRefused(Exception):
    """The guard refused a request before or instead of sending it.

    ``code`` is a stable machine-readable reason that callers record and may
    show; the message is for operators and never carries a credential.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
