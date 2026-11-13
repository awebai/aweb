"""Code-owned effect ports on the operation definition, not request selectors."""

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationEffect:
    provider: str | None = None
    signing_commit: str | None = None
    confirmation_commit: str | None = None


LOCAL_SIGNATURE = OperationEffect()
ENDORSEMENT = OperationEffect("admission", signing_commit="record_endorsement")
REGISTERED_MEMBERSHIP = OperationEffect("admission", confirmation_commit="confirm")
