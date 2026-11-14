"""Code-owned effect ports on the operation definition, not request selectors."""

from collections.abc import Callable
from dataclasses import dataclass

from .delivery_plans import certificate_delivery, owner_act_delivery, revocation_delivery


@dataclass(frozen=True)
class OperationEffect:
    provider: str | None = None
    signing_commit: str | None = None
    confirmation_commit: str | None = None
    delivery_plan: Callable | None = None
    cache_tolerates_unavailable: bool = False
    invalidates_membership: bool = False


LOCAL_SIGNATURE = OperationEffect(delivery_plan=owner_act_delivery)
ENDORSEMENT = OperationEffect("admission", signing_commit="record_endorsement")
REGISTERED_MEMBERSHIP = OperationEffect("admission", confirmation_commit="confirm", delivery_plan=certificate_delivery, cache_tolerates_unavailable=True, invalidates_membership=True)
REVOKED_MEMBERSHIP = OperationEffect("admission", confirmation_commit="confirm", delivery_plan=revocation_delivery, invalidates_membership=True)
OWNER_REVOKED_MEMBERSHIP = OperationEffect("owner_removal", confirmation_commit="confirm", delivery_plan=revocation_delivery, invalidates_membership=True)
