"""Signed owner effects use the original handoff factory and transaction."""

import secrets
from functools import partial

import pytest
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import PrincipalKey, assign, has_role
from aweb_naapp.runtime.approvals import Approvals, PgApprovalStore
from fastapi import HTTPException

from aweb_secrets.change_sets import ChangeSetPolicies
from aweb_secrets.console_values import ConsoleValues
from aweb_secrets.containment import Containment, ContainmentRefused
from aweb_secrets.custody import (
    Custody,
    LocalKeyFileProvider,
    apply_custody_migrations,
    encode_value,
)
from aweb_secrets.tokens import ProcessTokenCache
from tests.test_change_sets import Inbox
from tests.test_handoff_sessions import journey as journey
from tests.test_handoff_sessions import world as world
from tests.test_owner_directory import Audit
from tests.test_production_handoffs import bound_console, current_session


@pytest.mark.parametrize("prepared", [True, False], ids=["same-factory", "missing-factory"])
async def test_signed_value_ingress_requires_its_factory_before_staging(
    journey, tmp_path, prepared
):
    w = journey.world
    await apply_custody_migrations(w.db)
    key_file = tmp_path / "custody-key"
    key_file.write_text(secrets.token_bytes(32).hex())
    key_file.chmod(0o600)
    custody = Custody(LocalKeyFileProvider(key_file), w.db)
    key, issued = await journey.open()
    current = await current_session(journey, key, issued)
    service = ConsoleValues(console=bound_console(journey, prepared=prepared), custody=custody)
    value = encode_value("bearer", {"value": secrets.token_hex(24)})
    if prepared:
        staged = await service.stage_backend_credential(
            current, installation_id=w.admitted.installation_id, value=value
        )
        assert staged.version == 1
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    else:
        with pytest.raises(HTTPException) as refused:
            await service.stage_backend_credential(
                current, installation_id=w.admitted.installation_id, value=value
            )
        assert (refused.value.status_code, refused.value.detail) == (
            401,
            "console_session_required",
        )
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 0


async def containment_service(journey, tmp_path, *, prepared=True):
    w = journey.world
    await apply_custody_migrations(w.db)
    await apply_idempotency_migrations(w.db)
    key_file = tmp_path / "custody-key"
    key_file.write_text(secrets.token_bytes(32).hex())
    key_file.chmod(0o600)
    approvals = Approvals(
        store=PgApprovalStore(w.db),
        policies=ChangeSetPolicies(w.db, w.directory),
        approvers=w.directory,
        delivery=Inbox(),
        authenticators=[w.passkeys.authenticator()],
        audit=Audit(w.db),
    )
    return Containment(
        db=w.db,
        fence=w.console.fence,
        approvals=approvals,
        custody=Custody(LocalKeyFileProvider(key_file), w.db),
        passkeys=w.passkeys,
        directory=w.directory,
        tokens=ProcessTokenCache(),
        governance=partial(w.credential_audit._producer().enqueue, hook="post-governance-hook"),
        credential_audit=w.credential_audit,
        prepare_key_bound=journey.factory.prepare if prepared else None,
    )


@pytest.mark.parametrize("prepared", [True, False], ids=["same-factory", "missing-factory"])
async def test_signed_containment_prepares_before_removing_a_role(journey, tmp_path, prepared):
    w = journey.world
    service = await containment_service(journey, tmp_path, prepared=prepared)
    target = PrincipalKey(w.admitted.team_id, journey.member.did_key)
    role = "secrets.role.deployers"
    async with w.db.transaction() as tx:
        await assign(tx, target, role)
    key, issued = await journey.open()
    current = await current_session(journey, key, issued)
    request = dict(
        admitted=w.admitted,
        session=current,
        request_id="remove-signed-member",
        action="remove-role-member",
        target=role,
        member_principal=target.principal_did,
    )
    if prepared:
        assert (await service.by_console(**request)).action == "remove-role-member"
        assert not await has_role(w.db, target, role)
    else:
        with pytest.raises(ContainmentRefused) as refused:
            await service.by_console(**request)
        assert (refused.value.status, refused.value.code) == (401, "console_session_required")
        assert await has_role(w.db, target, role)
