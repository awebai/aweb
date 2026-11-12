"""One local administrator action, then B3's existing exact UV registration.

The CLI admits the first association on the protected host. A browser link is
only a locator for that pending association, never authority to choose a human,
replace an authorizer, change contact, recover a credential or sign an act.
"""

from datetime import UTC, datetime
from uuid import uuid4

from aweb_naapp.console import ConsoleRoute, exact_body, require_json, text_field
from aweb_naapp.console.browser import (
    Ceremony,
    CeremonyCopy,
    ConsoleBrand,
    ConsoleShell,
    SignInCopy,
)
from aweb_naapp.runtime.links import link_verifier
from aweb_naapp.runtime.passkeys import EnrolmentRefused
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.signing import canonical_json_bytes
from awid.did import validate_stable_id
from fastapi import APIRouter, Depends, HTTPException, Request


def operator_inputs(requester, contact):
    try:
        if validate_stable_id(requester) != requester:
            raise ValueError()
        if (
            not isinstance(contact, str)
            or len(contact) > 254
            or contact.count("@") != 1
            or any(ch.isspace() or ord(ch) < 32 for ch in contact)
            or any(ch in contact for ch in "<>,;")
            or not all(contact.split("@"))
        ):
            raise ValueError()
    except (TypeError, ValueError):
        raise SignerRefused("bootstrap_input_invalid") from None
    return requester, contact


def binding_value(c):
    """Exact public authority/origin/policy admitted by the local action."""
    return canonical_json_bytes(
        {
            "context": c.context.fields(),
            "authority_key_did": c.authority.custody.team_key_did,
            "human_origin": c.passkeys.rp.origin,
            "policy_version": c.signer.policies.expected_version or 1,
        }
    ).decode()


async def bootstrap_record(c, tx, *, hold=False):
    return await tx.fetch_one(
        "SELECT * FROM {{tables.protected_operator_bootstraps}} "
        "WHERE service_id=$1 AND team_id=$2" + (" FOR UPDATE" if hold else ""),
        c.context.service_id,
        c.context.authority_id,
    )


def pending(c, row):
    if (
        row is None
        or row["consumed_at"] is not None
        or row["binding"] != binding_value(c)
    ):
        raise EnrolmentRefused("bootstrap unavailable")


async def check_binding(c, tx, row, *, hold=False):
    current = await c.authority.binding(tx, hold=hold)
    if (
        current["subject"] != row["subject"]
        or current["b3_scope"] != row["b3_scope"]
        or current["generation"] != c.context.generation
    ):
        raise EnrolmentRefused("bootstrap association changed")
    await c.signer.policies.current("aweb.human-assurance/1", tx=tx)
    approver = await tx.fetch_one(
        "SELECT * FROM {{tables.passkey_approvers}} WHERE subject=$1"
        + (" FOR SHARE" if hold else ""),
        row["subject"],
    )
    if (
        approver is None
        or approver["scope"] != row["b3_scope"]
        or approver["contact"] != row["contact"]
        or approver["superseded_at"] is not None
        or approver["pending_contact"] is not None
        or approver["effective_at"] > datetime.now(UTC)
    ):
        raise EnrolmentRefused("bootstrap approver changed")


async def initialise(c, *, requester, contact):
    """Called only by the OS-authorized operator command, never by a route.

    Repeating an identical still-pending action reissues its B3 link. Any
    history without our pending record refuses, including preexisting fixture
    rows, inactive bindings and consumed/revoked credentials. No recovery.
    """
    from aweb_naapp.runtime.passkeys import ProtectedBootstrap

    operator_inputs(requester, contact)
    if c.context.generation != 1 or (c.signer.policies.expected_version or 1) != 1:
        raise SignerRefused("bootstrap_not_initial")
    observed = await c.authority.observe(c.context, purpose="prepare")
    resolved = await c.registry.resolve_key_fresh(requester)
    if resolved.did_aw != requester:
        raise SignerRefused("requester_invalid")
    async with c.db.transaction() as tx:
        # Serializes first creation before either row exists. All following
        # invocations take the bootstrap and authority fences before B3.
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "protected-bootstrap:"
            + c.context.service_id
            + ":"
            + c.context.authority_id,
        )
        row = await bootstrap_record(c, tx, hold=True)
        if row is None:
            existing = await tx.fetch_value(
                "SELECT 1 FROM {{tables.protected_authorizer_bindings}} "
                "WHERE service_id=$1 AND team_id=$2 LIMIT 1",
                c.context.service_id,
                c.context.authority_id,
            )
            if existing:
                raise SignerRefused("bootstrap_existing_authority")
            subject, scope, bootstrap_id = (
                str(uuid4()),
                "protected-" + uuid4().hex,
                str(uuid4()),
            )
            evidence = ProtectedBootstrap(
                bootstrap_id=bootstrap_id,
                actor="operator_bootstrap",
                transaction_id=int(await tx.fetch_value("SELECT txid_current()")),
            )
            designation = await c.passkeys.designate_first(
                tx,
                scope=scope,
                subject=subject,
                contact=contact,
                evidence=evidence,
            )
            await tx.execute(
                "INSERT INTO {{tables.protected_authorizer_bindings}} "
                "(service_id,team_id,human_id,human_domain,generation,subject,b3_scope,policy_version,authority_kind,authority_domain) "
                "VALUES($1,$2,$3,$4,1,$5,$6,1,$7,$8)",
                c.context.service_id,
                c.context.authority_id,
                c.context.human_id,
                c.context.human_domain,
                subject,
                scope,
                c.context.authority_kind,
                c.context.authority_domain,
            )
            await tx.execute(
                "INSERT INTO {{tables.protected_requester_bindings}} (b3_scope,principal) VALUES($1,$2)",
                scope,
                requester,
            )
            await tx.execute(
                "INSERT INTO {{tables.protected_operator_bootstraps}} "
                "(service_id,team_id,bootstrap_id,binding,subject,b3_scope,requester,contact) "
                "VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                c.context.service_id,
                c.context.authority_id,
                bootstrap_id,
                binding_value(c),
                subject,
                scope,
                requester,
                contact,
            )
        else:
            pending(c, row)
            if row["requester"] != requester or row["contact"] != contact:
                raise SignerRefused("bootstrap_conflict")
            await check_binding(c, tx, row, hold=True)
            # Unlike reissue's active-key guard, ANY credential history closes
            # this path, including revoked credentials. Recovery is separate.
            if await tx.fetch_value(
                "SELECT 1 FROM {{tables.passkey_credentials}} WHERE subject=$1",
                row["subject"],
            ):
                raise SignerRefused("bootstrap_consumed")
            designation = await c.passkeys.reissue_enrolment(tx, scope=row["b3_scope"])
        observed.require_fresh()
    # B3's contract: never send a link before its designation commits. No
    # token is returned to stdout; only the recorded contact receives it.
    delivered = await c.passkeys.deliver(designation)
    return {"scope": designation.approver.scope, "delivery": str(delivered)}


class BootstrapCompletion:
    """Caller fence in the original B3 credential/audit/token transaction."""

    def __init__(self, c, observed, enrolment):
        self.c, self.observed, self.enrolment = c, observed, enrolment
        self.tx = None

    async def prepare(self, tx):
        c = self.c
        if self.tx is not None:
            raise EnrolmentRefused("bootstrap transaction reused")
        row = await bootstrap_record(c, tx, hold=True)
        pending(c, row)
        if (
            row["subject"] != self.enrolment["subject"]
            or row["b3_scope"] != self.enrolment["scope"]
        ):
            raise EnrolmentRefused("bootstrap token mismatch")
        await check_binding(c, tx, row, hold=True)
        if await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_credentials}} WHERE subject=$1",
            row["subject"],
        ):
            raise EnrolmentRefused("bootstrap already enrolled")
        link = await tx.fetch_one(
            "SELECT * FROM {{tables.passkey_enrolments}} WHERE enrolment_id=$1 FOR UPDATE",
            self.enrolment["enrolment_id"],
        )
        self.valid_link(link, used=False)
        self.observed.require_fresh()
        self.tx = tx

    def valid_link(self, row, *, used):
        if (
            row is None
            or row["subject"] != self.enrolment["subject"]
            or row["revoked_at"] is not None
            or (row["used_at"] is not None) != used
            or datetime.now(UTC) >= row["expires_at"]
        ):
            raise EnrolmentRefused("bootstrap link expired or changed")

    async def check(self, tx):
        if self.tx is not tx:
            raise EnrolmentRefused("bootstrap transaction mismatch")
        c = self.c
        row = await bootstrap_record(c, tx)
        pending(c, row)
        await check_binding(c, tx, row)
        await tx.execute(
            "UPDATE {{tables.protected_operator_bootstraps}} SET consumed_at=clock_timestamp() "
            "WHERE bootstrap_id=$1",
            row["bootstrap_id"],
        )
        link = await tx.fetch_one(
            "SELECT * FROM {{tables.passkey_enrolments}} WHERE enrolment_id=$1",
            self.enrolment["enrolment_id"],
        )
        # Last awaited read: preserve the original link/evidence deadline even
        # if the authority, B3 locks or local audit were slow. Any refusal rolls
        # back this marker together with link, credential and B3 audit.
        self.valid_link(link, used=True)
        self.observed.require_fresh()


async def prepare_completion(c, token):
    enrolment = await c.db.fetch_one(
        "SELECT e.enrolment_id,e.subject,a.scope FROM {{tables.passkey_enrolments}} e "
        "JOIN {{tables.passkey_approvers}} a USING(subject) WHERE e.verifier_sha256=$1",
        link_verifier(token),
    )
    if enrolment is None:
        raise EnrolmentRefused("enrolment unavailable")
    observed = await c.authority.observe(c.context, purpose="prepare")
    return BootstrapCompletion(c, observed, enrolment)


def bootstrap_router(c, *, csrf_key, limiter=None):
    """Existing packaged B3 page and POST bodies on the human origin only."""
    router = APIRouter(route_class=ConsoleRoute)

    async def admit(request):
        if limiter is not None:
            await limiter.admit(
                request, "protected.enrolment", bucket="protected.enrolment"
            )

    @router.post("/enrolment/options", dependencies=[Depends(require_json)])
    async def options(request: Request):
        await admit(request)
        body = await exact_body(request, {"link_token"})
        token = text_field(body, "link_token")
        try:
            # Refuse non-bootstrap links before issuing B3 options. This does
            # not consume a record or confer LOGIN/APPROVE authority.
            prepared = await prepare_completion(c, token)
            async with c.db.transaction() as tx:
                await prepared.prepare(tx)
            return dict(await c.passkeys.enrolment_options(token))
        except (EnrolmentRefused, SignerRefused):
            raise HTTPException(403, "enrolment_refused") from None

    @router.post("/enrolment", dependencies=[Depends(require_json)])
    async def complete(request: Request):
        await admit(request)
        body = await exact_body(request, {"link_token", "credential"})
        token = text_field(body, "link_token")
        if not isinstance(body["credential"], dict):
            raise HTTPException(400, "request_invalid")
        try:
            prepared = await prepare_completion(c, token)
            approver = await c.passkeys.complete_enrolment(
                token, body["credential"], fence=prepared
            )
        except (EnrolmentRefused, SignerRefused):
            raise HTTPException(403, "enrolment_refused") from None
        return {"scope": approver.scope}

    # The shell owns fragment scrubbing, browser WebAuthn and its assets. No
    # app installation, replacement JS, token query parameter or session mint.
    sign_in = SignInCopy(
        title="Protected signing",
        heading="Sign in",
        scoped_hint="Use your passkey.",
        unscoped_hint="Open your approval link.",
        button="Sign in",
        waiting="Waiting…",
        failed="Sign-in failed.",
        sign_out_failed="Sign-out failed.",
        reauth_heading="Sign in again",
        reauth_text="Use your passkey.",
        reauth_link="Sign in",
    )
    shell = ConsoleShell(ConsoleBrand("Protected signing", csrf_key, "", sign_in))
    pages = shell.bootstrap_router(
        CeremonyCopy(
            enrolment=Ceremony(
                "Set up protected signing",
                f"Register a passkey for {c.context.human_id}, controller {c.context.authority_id}. "
                "This enrolls only the administrator-selected authorizer; it approves no act.",
                "Register passkey",
                "Your passkey is registered. Open your approval link to sign in.",
            ),
            contact_proof=Ceremony(
                "Contact change unavailable",
                "Contact changes require the separately authorized recovery flow.",
                "Unavailable",
                "Contact changes are unavailable here.",
            ),
            missing_link="Open the complete link from your enrollment email.",
            completing="Waiting for your passkey…",
            failed="Enrollment was refused. Request a new link from your administrator.",
            continue_link="Sign in",
        )
    )
    # This host implements first enrollment only. The same packaged shell also
    # offers a contact page to other embeddings; do not advertise it here.
    pages.routes[:] = [
        route for route in pages.routes if route.path != "/contact-proof"
    ]
    router.include_router(pages)
    return router
