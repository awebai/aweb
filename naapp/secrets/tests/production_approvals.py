"""Observe production approval effects through the owning components (§10.4)."""

from typing import TYPE_CHECKING, Any

import httpx
from aweb_naapp.runtime.approvals import Approval, PgApprovalStore

if TYPE_CHECKING:
    from tests.test_production_bootstrap import ProductionRequest


async def stored_approval(root, *, pending: "ProductionRequest") -> Approval:
    """Read the actual B2 record using its published store interface."""
    store = PgApprovalStore(root[0].runtime.db())
    approval = await store.get_by_request(pending.reply["approval_ref"])
    assert approval is not None
    return approval


async def requester_status(root, *, ref: str) -> httpx.Response:
    """Read one caller-owned locator through the signed production route."""
    _, client, configured, member, *_ = root
    path = "/v1/status/" + ref
    return await client.get(
        configured.public_origin + path,
        headers=member.headers(aud=configured.public_origin, method="GET", path=path),
    )


async def requester_receipt(root, *, pending: "ProductionRequest") -> dict[str, Any]:
    """Fetch the requester's receipt, checking its original request and intent."""
    response = await requester_status(root, ref=pending.reply["request_ref"])
    assert response.status_code == 200
    receipt = response.json()
    assert receipt["request_id"] == pending.reply["request_id"]
    assert receipt["request_ref"] == pending.reply["request_ref"]
    return receipt
