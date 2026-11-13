"""Later/replacement/deployment roots through real operator and B3 stores.

Bodies require the authorized PG/customer-registry VM lane. Provisioning uses
the supported bootstrap and real UV completion, not seeded completion markers.
"""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.signing import canonical_json_bytes
from nacl.signing import SigningKey

from aweb.protected_signing.operator import run
from aweb.protected_signing.profile import ProtectedServiceProfile
from aweb.protected_signing.root_binding import bind_root
from tests.test_independent_protected_http import profile_for
from tests.test_independent_protected_signer import DOMAIN, TEAM, did
from tests.test_protected_admission_native import admission_world, admit_operation, endorse, execute, prepare, root_operation
from tests.test_protected_bootstrap_native import complete, first
from tests.test_protected_host_native import host_settings_for
from tests.test_protected_signer_host import CapturedMail

pytest_plugins = ("tests.test_independent_protected_signer",)


@asynccontextmanager
async def binding_world(world, tmp_path, *, complete_team=True):
    _, token = await first(world)
    if complete_team:
        await complete(world, token)
    async with admission_world(world, tmp_path) as a:
        yield a


@pytest_asyncio.fixture
async def bindings(world, tmp_path):
    async with binding_world(world, tmp_path) as a:
        yield a


async def new_deployment(a):
    key = SigningKey.generate()
    root = await a.w.registry.register_did(did(key), bytes(key))
    w = SimpleNamespace(**{**vars(a.w), "root": key, "root_id": root.did_aw})
    return SimpleNamespace(**{**vars(a), "w": w})


def inputs(a, *, replace_root=None):
    return {"human_id": a.w.context.human_id, "root_id": a.w.root_id, "teams": [TEAM], "replace_root": replace_root}


async def grant_count(a, principal):
    return await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_requester_bindings}} WHERE principal=$1 AND active=TRUE", principal)


@pytest.mark.asyncio
async def test_real_operator_binds_a_later_root_to_both_scopes_and_both_deployments_admit(bindings, tmp_path):
    a = bindings
    second = await new_deployment(a)  # Registered only after the first bootstrap.
    assert (await prepare(second, root_operation(second))).status_code == 403
    settings = host_settings_for(a.w, tmp_path)
    fields = profile_for(a.w).fields()
    fields["bindings"].append({"scope": a.human.context.fields(), "authority_key_did": did(a.w.human_key),
        "policy": {"ref": "aweb.human-assurance/1", "version": 1}})
    profile = ProtectedServiceProfile.from_json(canonical_json_bytes(fields))
    settings.profile_file.write_bytes(canonical_json_bytes(fields))
    manifest = tmp_path / "private-keys.json"
    manifest.write_bytes(canonical_json_bytes({did(a.w.controller): str(settings.controller_key_file),
        did(a.w.human_key): str(tmp_path / "human-custody" / "signing.key")}))
    settings.controller_keys_file = manifest
    args = SimpleNamespace(command="bind-root", human=a.w.context.human_id,
        root=second.w.root_id, team=[TEAM], replace_root=None)
    result = await run(args, settings, profile=profile, scope=a.w.context.fields(),
        mailer=CapturedMail(), registry_transport=a.w.host.transport)
    assert result["root_id"] == second.w.root_id and result["root_key"] == did(second.w.root)
    assert len(result["scopes"]) == 2 and {scope["authority"]["kind"] for scope in result["scopes"]} == {"human_identity", "team_controller"}
    assert await grant_count(a, second.w.root_id) == 2
    assert await grant_count(a, a.w.root_id) == 2
    # Binding only admits requests. No child admission before the new root's
    # separate live endorsement; no fake UV or reuse of the first root's act.
    assert (await prepare(second, admit_operation(second))).status_code == 403
    await endorse(a)
    await endorse(second)
    for deployment in (a, second):
        operation = admit_operation(deployment)
        assert (await prepare(deployment, operation)).status_code == 200
        response = await execute(deployment, operation)
        assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    assert await a.w.db.fetch_value("SELECT count(DISTINCT root_id) FROM {{tables.protected_root_admissions}}") == 2
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_operator_bootstraps}} WHERE consumed_at IS NOT NULL") == 2
    assert await bind_root(a.group, **inputs(second)) == result
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_root_requester_bound'") == 1


@pytest.mark.asyncio
async def test_replacement_of_a_revoked_root_retires_only_its_named_grants(bindings):
    a = bindings
    await endorse(a)
    head = await a.w.db.fetch_value("SELECT certificate_id FROM {{tables.protected_root_endorsements}} WHERE root_id=$1", a.w.root_id)
    await a.w.registry.revoke_id_certificate(DOMAIN, a.w.root_id,
        signer=lambda raw: (did(a.w.human_key), a.w.human_key.sign(raw).signature), expected_head=head)
    replacement = await new_deployment(a)
    result = await bind_root(a.group, **inputs(replacement, replace_root=a.w.root_id))
    assert result["replaced_root"] == a.w.root_id
    assert await grant_count(a, a.w.root_id) == 0
    assert await grant_count(a, replacement.w.root_id) == 2
    await endorse(replacement)
    operation = admit_operation(replacement)
    assert (await prepare(replacement, operation)).status_code == 200
    assert (await execute(replacement, operation)).json()["state"] == "committed"
    with pytest.raises(SignerRefused):
        await bind_root(a.group, **inputs(a))


@pytest.mark.asyncio
async def test_retired_requester_is_not_implicitly_reactivated_and_exact_replacement_is_idempotent(bindings):
    a = bindings
    second = await new_deployment(a)
    original = await bind_root(a.group, **inputs(second, replace_root=a.w.root_id))
    assert await bind_root(a.group, **inputs(second, replace_root=a.w.root_id)) == original
    with pytest.raises(SignerRefused, match="requester_binding_retired"):
        await bind_root(a.group, **inputs(a))
    assert await grant_count(a, a.w.root_id) == 0 and await grant_count(a, second.w.root_id) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing_human_custody", "another_human", "another_team", "retired_credential"])
async def test_binding_requires_the_exact_completed_human_and_each_controller(bindings, case):
    a = bindings
    second = await new_deployment(a)
    c, request = a.group, inputs(second)
    if case == "missing_human_custody":
        c = a.w.app
    if case == "another_human":
        request["human_id"] = a.w.root_id
    if case == "another_team":
        request["teams"] = ["unloaded:customer.example"]
    if case == "retired_credential":
        await a.w.db.execute("UPDATE {{tables.passkey_credentials}} SET revoked_at=clock_timestamp()")
    with pytest.raises(SignerRefused):
        await bind_root(c, **request)
    assert await grant_count(a, second.w.root_id) == 0


@pytest.mark.asyncio
async def test_pending_first_enrollment_cannot_grant_a_later_root(world, tmp_path):
    async with binding_world(world, tmp_path, complete_team=False) as a:
        second = await new_deployment(a)
        with pytest.raises(SignerRefused, match="bootstrap_incomplete"):
            await bind_root(a.group, **inputs(second))
        assert await grant_count(a, second.w.root_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["audit_unavailable", "final_deadline", "policy_changed"])
async def test_final_failures_roll_back_both_grants_retirement_and_audit(bindings, monkeypatch, case):
    a = bindings
    second = await new_deployment(a)
    original = a.human.audit.emit

    async def fail(event, transaction):
        if event.kind.value == "protected_root_requester_bound":
            if case == "audit_unavailable":
                raise RuntimeError("audit unavailable")
            await original(event, transaction)
            if case == "final_deadline":
                timer = a.human.authority.timer
                monkeypatch.setattr(a.human.authority, "timer", lambda: timer() + 61)
            if case == "policy_changed":
                await transaction.execute("UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=policy_version+1")
        else:
            await original(event, transaction)

    monkeypatch.setattr(a.human.audit, "emit", fail)
    with pytest.raises((SignerRefused, RuntimeError)):
        await bind_root(a.group, **inputs(second, replace_root=a.w.root_id))
    assert await grant_count(a, second.w.root_id) == 0
    assert await grant_count(a, a.w.root_id) == 2
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_root_requester_bound'") == 0
