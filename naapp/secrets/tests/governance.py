"""Trusted registration-view input for the real signed governance outbox tests."""

from datetime import UTC, datetime, timedelta

from aweb_naapp.hooks.producer import Registration, RegistrationView

TEAM = "backend:acme.com"


def view():
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (
            Registration(
                "local-logs-binding",
                "https://logs.example",
                "POST",
                "/hooks/ingest",
                now - timedelta(hours=1),
            ),
        ),
    )


async def credential_audit(*, db, passkeys, owner, fence, admitted, origin, producer=None):
    """Compose the real required B3 branch for caller fixtures."""
    import os
    from dataclasses import replace

    from aweb_naapp.hooks.producer import HookProducer, ServerProducer
    from aweb_naapp.outbox import apply_outbox_migrations
    from aweb_naapp.runtime.approvals import PgApprovalStore

    from aweb_secrets.credential_audit import CredentialAudit

    await apply_outbox_migrations(db)
    store = PgApprovalStore(db)
    if producer is None:
        producer = HookProducer(
            ServerProducer.app(
                origin=origin,
                app_id=admitted.app_id,
                installation_id=admitted.installation_id,
                generation=admitted.generation,
                kid="test-key",
                seed=os.urandom(32),
            )
        )

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    async def registration(team_id):
        assert team_id == admitted.team_id
        return replace(view(), team_id=team_id)

    audit = CredentialAudit(
        db=db,
        app_id=admitted.app_id,
        fence=fence,
        contexts=passkeys._proof_context,
        owner_act_scope=owner.verifier.scope,
        producer=lambda **scope: producer,
        passkeys=lambda: passkeys,
        approval=approval,
        registration_view=registration,
        max_backlog_age=timedelta(minutes=5),
    )
    await audit.migrate()
    passkeys._audit = audit
    return audit
