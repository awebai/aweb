"""The owner page after an owner-started removal expires.

Only the signer's own stored final refusal of a definitely unsigned request
lets the page forget the tab's saved selection; a signed but unconfirmed
request stays unresolved and keeps it.
"""

from datetime import timedelta

import pytest

from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_owner_initiation_native import owner_http, selection
from tests.test_protected_owner_removal_native import legacy_member

pytest_plugins = ("tests.test_independent_protected_signer",)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unsigned", "signed"])
async def test_only_a_stored_unsigned_expiry_lets_the_page_start_a_new_removal(admissions, tmp_path, monkeypatch, state):
    from aweb_naapp.runtime.protected_signer import OperationReceipt

    from aweb.protected_signing.owner import owner_page_html, owner_view

    a = admissions
    _, certificate = await legacy_member(a, "unknown")
    body = selection(certificate)
    async with owner_http(a, tmp_path) as (client, headers, _):
        signer = a.w.app.signer
        signer.mailed_approval_wait = timedelta(seconds=30)
        response = await client.post("/governance/operations", json=body, headers=headers)
        assert response.status_code == 200, response.text
        if state == "signed":
            async def no_release(operation_id, *args, **kwargs):
                return OperationReceipt(operation_id, "unknown", code="external_effect_unresolved")

            monkeypatch.setattr(signer, "_reconcile_retained", no_release)
            path = "/handoff/" + response.json()["handoff_id"] + "/governance"
            options = await client.post(path + "/options", json={}, headers=headers)
            answer = await client.post(path + "/execute", json={"assertion": a.w.device.get(options.json())},
                headers=headers)
            assert answer.json()["state"] == "unknown", answer.text
        row = await a.w.db.fetch_one(
            "SELECT expires_at FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", body["operation_id"])
        expired = row["expires_at"] + timedelta(seconds=1)
        monkeypatch.setattr(signer, "clock", lambda: expired)
        # The person's own next Remove: the same saved selection.
        retry = await client.post("/governance/operations", json=body, headers=headers)
        html = owner_page_html(await owner_view(a.w.app, scope=a.w.human.b3_scope, subject=a.w.human.subject,
            now=expired))
        marker = f'data-final-operation="{body["operation_id"]}"'
        if state == "unsigned":
            assert retry.status_code == 410 and retry.json() == {"detail": "operation_expired"}
            # Stored final: the reloaded page lets the tab forget the selection.
            assert marker in html
        else:
            assert retry.status_code == 200
            # Possibly applied: the page keeps the selection and its pointer.
            assert marker not in html and "not confirmed yet" in html
