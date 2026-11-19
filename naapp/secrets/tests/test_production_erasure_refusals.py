"""Both real containment transports roll back when pin erasure cannot be recorded."""

import json
from enum import StrEnum
from uuid import uuid4

import pytest

from aweb_secrets.erasure import ErasureFailure, ErasureUnavailable, operator_receipts
from aweb_secrets.revisions import config_revision
from tests.production_approvals import stored_approval
from tests.production_database import prepared_service_databases as prepared_service_databases
from tests.test_production_bootstrap import enrolled_owner
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_runner_dispatch import runner_headers
from tests.test_use_approvals import SECRET


class ContainmentTransport(StrEnum):
    MEMBER_API = "member_api"
    OWNER_CONSOLE = "owner_console"


async def _containment_request(
    root, *, transport: ContainmentTransport, csrf_token: str, body: dict
):
    _, client, configured, member, installed, *_ = root
    raw = json.dumps(body).encode()
    if transport is ContainmentTransport.MEMBER_API:
        path = "/v1/containment"
        origin = configured.public_origin
        headers = member.headers(aud=origin, method="POST", path=path, body=raw)
        headers["Content-Type"] = "application/json"
    else:
        path = f"/installations/{installed['installation_id']}/containment"
        origin = configured.console_origin
        headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    return await client.post(origin + path, content=raw, headers=headers)


async def _effects(root, *, pending):
    service, _, _, member, installed, *_ = root
    db = service.runtime.db()
    identity = (installed["installation_id"], member.team_id)
    approval = await stored_approval(root, pending=pending)
    return {
        "secrets": await db.fetch_all(
            "SELECT secret_id,state FROM secrets WHERE installation_id=$1 AND team_id=$2"
            " ORDER BY secret_id",
            *identity,
        ),
        "custody": await db.fetch_all(
            "SELECT secret_id,last_version,disabled_at FROM custody_secrets"
            " WHERE installation_id=$1 AND team_id=$2 ORDER BY secret_id",
            *identity,
        ),
        "pins": await db.fetch_all(
            "SELECT dispatch_id,secret_id,version FROM run_redaction_pins"
            " WHERE installation_id=$1 AND team_id=$2 ORDER BY dispatch_id,secret_id",
            *identity,
        ),
        "revision": await config_revision(db, identity[0], team_id=identity[1]),
        "containment": await db.fetch_value(
            "SELECT count(*) FROM containment_receipts WHERE installation_id=$1 AND team_id=$2",
            *identity,
        ),
        "erasures": len(await operator_receipts(db)),
        "approval": (approval.state, approval.consumed_operation_id),
    }


@pytest.mark.parametrize("transport", list(ContainmentTransport))
async def test_erasure_storage_refusal_rolls_back_the_actual_containment_request(
    root, prepared_service_databases, transport: ContainmentTransport, *, onepassword_values
):
    service, client, configured, *_ = root
    pending = await admitted_run(root, onepassword_values=onepassword_values)
    claim_path = "/runner/v1/claim"
    claim = await client.post(
        configured.public_origin + claim_path,
        content=b"{}",
        headers=runner_headers(pending, configured.public_origin, claim_path),
    )
    assert claim.status_code == 200
    holder = await enrolled_owner(root)
    before = await _effects(root, pending=pending)
    assert len(before["pins"]) == 1
    body = {"request_id": uuid4().hex, "action": "disable-secret", "target": SECRET["secret_id"]}
    async with prepared_service_databases.unavailable_erasure_storage(service.runtime.db()):
        response = await _containment_request(
            root, transport=transport, csrf_token=holder.csrf_token, body=body
        )
    assert response.status_code == 503
    assert response.json() == {
        "detail": ErasureFailure.UNAVAILABLE,
        "message": str(ErasureUnavailable(ErasureFailure.UNAVAILABLE)),
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert await _effects(root, pending=pending) == before
    # Restoring ledger writes makes the same supported operation succeed once.
    accepted = await _containment_request(
        root, transport=transport, csrf_token=holder.csrf_token, body=body
    )
    assert accepted.status_code == 200
    after = await _effects(root, pending=pending)
    assert after["pins"] == []
    assert after["erasures"] == before["erasures"] + 1
    assert after["containment"] == before["containment"] + 1
    assert after["revision"] == before["revision"] + 1
    assert any(
        row["secret_id"] == SECRET["secret_id"] and row["state"] == "disabled"
        for row in after["secrets"]
    )
