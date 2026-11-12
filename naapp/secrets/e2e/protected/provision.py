"""Trusted fixture provisioning for the protected round trip (HOST.md).

Runs inside the protected container, as its process uid, with the host's own
AWEB_PROTECTED_* settings, so custody's ownership and mode checks hold. It
declares the disposable lane's authorizer, requester and approver rows and
enrols the approver's passkey through B3's own APIs with a browser
attestation. It never inserts a credential, session, assertion or success row.

  provision.py setup --human-id H --requester R --contact C
  provision.py options --token T            (prints enrolment options JSON)
  provision.py complete --token T             (attestation JSON on stdin)
  provision.py evidence --operation-id ID [...]   (read only: what was signed)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from contextlib import asynccontextmanager

from aweb.protected_signing.composition import IndependentProtectedSigner
from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb.protected_signing.host import HostSettings, _member_keys
from aweb.protected_signing.notifications import ProtectedNotifications
from aweb.protected_signing.profile import ProtectedServiceProfile
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.strictjson import parse_strict
from awid.db_config import build_database_config
from awid.registry import RegistryClient
from pgdbm import AsyncDatabaseManager

B3_SCOPE = "controller-authorizer"


@asynccontextmanager
async def composition():
    """The host's composition from its settings, without startup validation:
    provisioning is what makes that validation pass."""
    settings = HostSettings()
    profile = ProtectedServiceProfile.from_json(settings.profile_file.read_bytes())
    scope = parse_strict(settings.scope_file.read_bytes())
    context = profile.binding_for(scope).context()
    custody = ProtectedControllerCustody(
        service_id=context.service_id,
        team_id=context.authority_id,
        domain=context.authority_domain,
        key_file=settings.controller_key_file,
        worker_uids=frozenset(settings.worker_uids),
    )
    db = AsyncDatabaseManager(
        build_database_config(
            connection_string=settings.database_url.get_secret_value(),
            schema=settings.database_schema,
            min_connections=1,
            max_connections=2,
        )
    )
    await db.connect()
    registry = RegistryClient(
        registry_url=profile.registry_origin,
        member_signing_keys=_member_keys(settings.member_keys_file),
    )
    try:
        yield IndependentProtectedSigner.from_profile(
            db,
            profile=profile,
            scope=scope,
            registry_client=registry,
            custody=custody,
            delivery=ProtectedNotifications(
                db=db,
                mailer=Mailer(EmailSettings.from_env("AWEB_PROTECTED_")),
                human_origin=profile.human_origin,
            ),
        )
    finally:
        await registry.aclose()
        await db.disconnect()


async def setup(args) -> dict:
    async with composition() as c:
        await c.migrate()
        await apply_console_migrations(c.db)
        ctx, subject = c.context, str(uuid.uuid4())
        await c.db.execute(
            "INSERT INTO {{tables.protected_authorizer_bindings}} "
            "(service_id,team_id,human_id,human_domain,generation,subject,b3_scope,policy_version) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,1)",
            ctx.service_id, ctx.authority_id, args.human_id, ctx.human_domain, ctx.generation, subject, B3_SCOPE,
        )
        await c.db.execute(
            "INSERT INTO {{tables.protected_requester_bindings}} (b3_scope,principal) VALUES($1,$2)",
            B3_SCOPE, args.requester,
        )
        await c.db.execute(
            "INSERT INTO {{tables.passkey_approvers}} "
            "(subject,scope,contact,designated_by,designated_at,effective_at) "
            "VALUES($1,$2,$3,'operator_bootstrap',now(),now())",
            subject, B3_SCOPE, args.contact,
        )
        async with c.db.transaction() as tx:
            designation = await c.passkeys.reissue_enrolment(tx, scope=B3_SCOPE)
        delivered = await c.passkeys.deliver(designation)
        return {"b3_scope": B3_SCOPE, "subject": subject, "delivery": str(delivered)}


async def options(args) -> dict:
    async with composition() as c:
        return dict(await c.passkeys.enrolment_options(args.token))


async def complete(args) -> dict:
    async with composition() as c:
        attestation = json.loads(sys.stdin.read())
        await c.passkeys.complete_enrolment(args.token, attestation)
        return {"enrolled": True}


async def evidence(args) -> dict:
    """Each operation's stored outcome: whether it holds a signed result, and
    its refusal code. Read only; the evidence that nothing else was signed."""
    async with composition() as c:
        rows = await c.db.fetch_all(
            "SELECT operation_id, result IS NOT NULL AS signed, refusal_code "
            "FROM {{tables.protected_signer_operations}} WHERE operation_id = ANY($1::text[])",
            args.operation_id,
        )
        return {row["operation_id"]: {"signed": row["signed"], "refusal_code": row["refusal_code"]} for row in rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    s = commands.add_parser("setup")
    s.add_argument("--human-id", required=True)
    s.add_argument("--requester", required=True)
    s.add_argument("--contact", required=True)
    o = commands.add_parser("options")
    o.add_argument("--token", required=True)
    c = commands.add_parser("complete")
    c.add_argument("--token", required=True)
    v = commands.add_parser("evidence")
    v.add_argument("--operation-id", action="append", required=True)
    args = parser.parse_args()
    result = asyncio.run(
        {"setup": setup, "options": options, "complete": complete, "evidence": evidence}[args.command](args)
    )
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
