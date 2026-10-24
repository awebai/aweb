"""Owner configuration over real S4/B2/B3/PG, with signed governance receipts.

The SDK Item projection here supplies local staged metadata; HO6 and the real
root journey separately prove external-vault access and browser composition.
"""

from copy import deepcopy

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.custody import CustodyUnavailable
from aweb_secrets.custody.opening import active_binding
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import config_revision
from tests.test_change_records import ITEMS
from tests.test_change_set_onepassword import binding_item, staged, token_item, view
from tests.test_change_sets import ALICE, TEAM, enrol_owner, grant_role
from tests.test_change_sets import world as _world
from tests.test_console_changes import ROOT, approve, clients, sign_in

world = _world


async def configuration_draft(w, human, headers):
    record, token, binding, value = await staged(w)
    response = await human.post(
        ROOT,
        headers=headers,
        json={
            "changes": [
                {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
                binding_item(binding),
                token_item(token),
            ],
            "sealed": [
                {"secret_id": token.secret_id, "version": token.version},
                {"secret_id": binding.context.secret_id, "version": binding.context.version},
            ],
            "reason": "Configure a vault-backed API credential",
        },
    )
    assert response.status_code == 201
    assert value not in response.text
    return response.json(), record, token, binding, value


async def test_owner_confirms_vault_reference_with_metadata_and_atomic_governance(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, agent):
        headers = await sign_in(w, human, scope)
        drafted, record, token, binding, value = await configuration_draft(w, human, headers)
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
        with pytest.raises(CustodyUnavailable):
            await active_binding(w.db, binding.context)
        assert (await agent.get(ROOT + "/" + drafted["change_id"])).status_code == 404
        path = await approve(w, human, headers, drafted)
        confirmed = await human.post(path + "/confirm", json={}, headers=headers)
        assert confirmed.status_code == 200
        assert confirmed.json()["revision"] == 1
        assert value not in confirmed.text
    assert (await active_binding(w.db, binding.context)).credential_context == token
    assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.CONSUMED
    rows = await w.db.fetch_all(
        "SELECT payload, signature FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
    )
    events = [verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields for row in rows]
    assert sorted(event["payload"]["act"] for event in events) == [
        "resource.created",
        "resource.version_added",
        "resource.version_added",
    ]
    commitments = {event["payload"]["approval_evidence_sha256"] for event in events}
    assert len(commitments) == 1 and len(commitments.pop()) == 64
    for event in events:
        assert event["actor"] == {"authority_mode": "system", "attestations": []}
        assert event["payload"]["authority"] == "passkey_session"
        assert event["payload"]["approval_id"] == drafted["approval_id"]
        assert value not in str(event)
        assert binding.after["vault_id"] not in str(event)
        assert binding.after["item_id"] not in str(event)


@pytest.mark.parametrize("proof_available", [False, True])
async def test_configuration_refusal_keeps_revision_activation_and_decision_inert(
    world, proof_available
):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")

    class Targets:
        async def view(self, team_id, hook):
            assert team_id == TEAM and hook == "post-governance-hook"
            return view() if not proof_available else None

    async with clients(w, registrations=Targets()) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted, _, token, binding, _ = await configuration_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        if not proof_available:
            decision = await w.approvals.get(drafted["approval_id"])
            await w.db.execute(
                "DELETE FROM {{tables.passkey_proofs}} WHERE evidence_ref=$1",
                decision.decided_by.evidence_ref,
            )
        refused = await human.post(path + "/confirm", json={}, headers=headers)
        assert refused.status_code == 409
        assert refused.json()["detail"] == (
            "audit_target_unavailable" if proof_available else "passkey_proof_unavailable"
        )
    assert await config_revision(w.db, INSTALLATION_ID) == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
    await w.custody.backend_credential_preview.open(token)
    with pytest.raises(CustodyUnavailable):
        await active_binding(w.db, binding.context)


async def test_owner_configuration_records_share_the_single_proof_bound_writer(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    items = [
        deepcopy(ITEMS[kind]) for kind in ("secret", "destination", "operation", "policy", "grant")
    ]
    by_kind = {item["kind"]: item for item in items}
    operation = by_kind["operation"]["after"]
    pin = {
        "operation_id": operation["operation_id"],
        "digest": OperationTemplate.from_after(operation).digest,
    }
    by_kind["policy"]["after"]["operations"] = [pin]
    policy = Policy.from_body(
        {key: value for key, value in by_kind["policy"]["after"].items() if key != "v"}
    )
    by_kind["policy"]["ref"] = policy.digest
    by_kind["grant"]["after"]["policy_digest"] = policy.digest
    by_kind["grant"]["after"]["operations"] = [pin]
    by_kind["destination"]["after"].update(path="/v1/charges/**", methods=["GET"], header_allow=[])
    items.append(grant_role(ALICE))
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        response = await human.post(
            ROOT,
            headers=headers,
            json={"changes": items, "sealed": [], "reason": "Configure API use"},
        )
        assert response.status_code == 201
        drafted = response.json()
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
        path = await approve(w, human, headers, drafted)
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 200
    assert await config_revision(w.db, INSTALLATION_ID) == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.destinations}}") == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.grants}}") == 1
    rows = await w.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
    )
    events = [verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields for row in rows]
    assert sorted(event["payload"]["act"] for event in events) == [
        "grant.created",
        "policy.changed",
        "resource.created",
        "resource.created",
        "resource.created",
        "role.designated",
    ]
    assert len({event["payload"]["approval_evidence_sha256"] for event in events}) == 1
    role = next(
        event["payload"] for event in events if event["payload"]["act"] == "role.designated"
    )
    assert role["subject_ref"] == "member:" + ALICE.principal_did
    assert role["role"] == "secrets.role.deployers"


async def test_job_and_runner_creation_use_shared_confirmation_and_protected_result(world):
    from aweb_secrets.jobs import apply_job_migrations, current_job
    from aweb_secrets.runners import apply_runner_migrations, mint_runner_id
    from tests.test_change_set_runners import runner_item
    from tests.test_jobs import after as job_after

    w = world
    await apply_job_migrations(w.db)
    await apply_runner_migrations(w.db)
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    runner_id = mint_runner_id()
    body = job_after()
    body["runner_ids"] = [runner_id]
    body["credentials"][0]["secret_ref"] = ITEMS["secret"]["ref"]
    body["env"]["DB_ADMIN"]["$credential"] = ITEMS["secret"]["ref"]
    runner = runner_item(runner_id)
    runner["after"]["allowed_jobs"] = [body["job_id"]]
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await human.post(
            ROOT,
            headers=headers,
            json={
                "changes": [
                    {"kind": "job", "op": "create", "ref": body["job_id"], "after": body},
                    deepcopy(ITEMS["secret"]),
                    runner,
                ],
                "sealed": [],
                "reason": "Register a pinned durable job",
            },
        )
        assert drafted.status_code == 201
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.current_jobs}}") == 0
        path = await approve(w, human, headers, drafted.json())
        response = await human.post(path + "/confirm", json={}, headers=headers)
        assert response.status_code == 200
        [registration] = response.json()["runner_registrations"]
        assert registration["runner_id"] == runner_id
        assert registration["registration_required"] is True
        assert registration["registration_code"]
        async with w.db.transaction() as tx:
            stored = await current_job(tx, INSTALLATION_ID, body["job_id"])
        assert stored.after == body
        assert registration["registration_code"] not in (await human.get(path)).text
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
    rows = await w.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
    )
    events = [verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields for row in rows]
    job_event = next(
        event["payload"] for event in events if event["payload"].get("resource_type") == "job"
    )
    assert job_event["act"] == "resource.created" and job_event["resource_ref"] == body["job_id"]
    assert any(event["payload"]["act"] == "runner.registered" for event in events)
    assert registration["registration_code"] not in str(events)


async def test_job_definition_refuses_fields_from_another_credential_family_before_draft(world):
    from tests.test_jobs import after as job_after

    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    secret = deepcopy(ITEMS["secret"])
    secret["after"]["kind"] = "basic"
    body = job_after()
    body["credentials"][0]["secret_ref"] = secret["ref"]
    body["env"]["DB_ADMIN"]["$credential"] = secret["ref"]
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        refused = await human.post(
            ROOT,
            headers=headers,
            json={
                "changes": [
                    secret,
                    {"kind": "job", "op": "create", "ref": body["job_id"], "after": body},
                ],
                "sealed": [],
                "reason": "Invalid field family",
            },
        )
        assert refused.status_code == 409
        assert refused.json() == {"detail": "job_source_invalid"}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
