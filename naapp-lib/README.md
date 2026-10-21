# aweb-naapp

The reusable Native Agentic App (naapp) docs surface. Every naapp built with it
serves the same standard surface — so the standard is shared code, not a doc
copied by hand.

An app supplies its canonical `aweb-app.json` manifest, a `SiteConfig` (brand,
nav, footer), and its own landing body, and gets:

- the **aweb design system** (Paper/Clay), vendored and sha-pinned, served at
  `/css/aweb.css`;
- the **shared chrome** — head, header, footer, theme toggle, and copy button;
- **manifest-driven llms.txt blocks** — the operations list and the
  team-certificate authentication section;
- the **`/reference` page** — every operation in parallel as the canonical
  `aw <verb>` command and the raw HTTP wire format, with the honest team-cert v2
  envelope linked to the conformance vector.

```python
import aweb_naapp as naapp

site = naapp.SiteConfig(
    origin="https://library.aweb.ai",
    brand="library",
    title="library — agent profiles for AWID teams",
    description="...",
    nav_links=(naapp.NavLink("Reference", "/reference"), ...),
    footer_blurb="...",
    footer_columns=(...),
    footer_bottom="library is a Native Agentic App on the aweb.ai hub. AWID is the identity authority.",
)

reference_html = naapp.render_reference(manifest, site, verb="library")
landing_html = naapp.page(site, body_html, include_copy_llms=True)
css_bytes = naapp.aweb_css()
```

The docs surface is pure standard library. Request-time runtime code (the
team-auth verifier, approvals, passkeys, and team-server discovery from the
team's AWID `aweb.team-server/1` record) lives under `aweb_naapp.runtime` and
needs the `runtime` extra: `aweb-naapp[runtime]`. Two parts the core server
shares import without it: the durable outbox, `aweb_naapp.outbox`
(`aweb-naapp[outbox]`), and the signing-key reader, `aweb_naapp.signing_key`
(`aweb-naapp[signing-key]`).

The egress guard, `aweb_naapp.egress`, is for naapps that call an external
service with their own credential. It needs only the `egress` extra,
`aweb-naapp[egress]`, and none of the runtime. It canonicalizes and matches
outbound URLs under the contracts in `docs/vectors/egress-url-v2.json` and
`docs/vectors/egress-address-v1.json`, resolves names itself and refuses any
denied address, and sends a request only to the destination it matches,
through one pinned, verified connection. Redirects come back as responses, no proxy is read from
the environment, and a failure is classed as not sent or of unknown outcome.

The email sender, `aweb_naapp.email`, sends a naapp's links and notices, one
recipient per message, over SMTP with TLS required and the certificate
verified. It is pure standard library and needs no extra.
`EmailSettings.from_env(prefix)` reads `<PREFIX>EMAIL_SMTP_HOST`, `_SMTP_PORT`,
`_TLS` (`starttls` or `implicit`), `_USERNAME`, `_FROM`, an optional
`_CA_FILE`, and the password from the key file named by `_PASSWORD_FILE`
(`aweb_naapp.key_file`), never from the environment; anything missing or
malformed fails at startup. A failed send raises `EmailNotSent` with a code, and
neither errors nor logs carry the body or the full recipient.

A server that produces hook events (`docs/hook-events.md`) uses
`aweb_naapp.hooks.producer` and `aweb_naapp.hooks.transport`, with the `hooks`,
`outbox` and `egress` extras. `HookProducer.enqueue(tx, ...)` signs an event and
stores it on the outbox's `hooks` channel in the effect's own transaction. An
audit-critical event is refused with `audit_target_unavailable` unless the
registration view the caller read beforehand is fresh and holds a registration
owed it. The drain resolves deliveries with `hook_targets(registrations)`, and
`HookTransport` re-checks each binding, signs a `hook-delivery` request and sends
it through the egress guard to the binding's endpoint only.

Operators: a hook target is sent to as a public destination. A self-hosted
operator who also wants hooks to reach targets inside its own network allows
internal destinations on the egress and passes that network as
`HookTransport(internal_cidr=...)`; a target the guard refuses as a private
address is then tried once more inside that network, and only there. This is
an opt-in to server-side requests into your network: any activated binding
whose origin resolves inside `internal_cidr` becomes reachable, and a
third-party app's owner controls its own DNS, so keep `internal_cidr` as
narrow as the hosts of your own apps. A hosted deployment allows neither, so
private addresses are never reached. Before rotating the producer's hook key,
drain the `hooks` channel: undelivered events carry the old key's signature,
and their deliveries would end rejected.

### Database schema

An app's tables live in `<PREFIX>DB_SCHEMA` (default `public`). The runtime pins
every connection's search_path to it, so the app works whatever its database
role's default search_path is. A new app should set its own schema: apps that
share one database also share the runtime's own tables (the outbox, observed
principals) unless their schemas differ.

### App keys

An app names its signing keys by kid, as key files:
`<PREFIX>APP_KEY_FILES='{"<kid>": "/run/secrets/<file>"}'`. A key file holds the
32-byte Ed25519 seed as 64 hex characters, with one trailing newline allowed. It
must be a regular file of at most 1 KiB, and must not be group- or world-writable. The manifest
declares which kid signs which purpose, and the app does not start unless the
configured key is the declared one. An app with `<PREFIX>APP_EVENTS_ORIGIN` set
(https, or http on loopback) must hold its declared app-event key. That key may instead be given as
`<PREFIX>APP_EMIT_KEY_SEED_HEX` with `<PREFIX>APP_EMIT_KID`, a form that signs
app events only.

### Health

`/live` reports the app's id and build commit. `/health` and `/ready` also run
the app's dependency checks and report each by name: `ready` is 503 when any
check fails, and `health` always answers 200. The runtime checks its database
and reports the age of its oldest undelivered outbox event
(`NaappRuntime.health_checks()`). An app adds its own as async callables that
return a `CheckResult`. A check that raises, or does not answer within 5 s,
fails, and its error is logged, never served. `/ready` serves only whether each
check passed; `/health` adds each check's detail, whose values are numbers,
booleans or null, never text. The routes are unauthenticated,
so the checks run at most once every 10 s: concurrent requests share the run in
flight, and later ones get its result until it expires.

### Agent and human origins

An app with pages for people in a browser serves them on their own origin.
`aweb_naapp.runtime.origins.split_origins(agent_app, human_app, agent_origin=...,
human_origin=...)` is one ASGI app that dispatches on `Host`:

- the agent origin serves the runtime's app, with no cookies in either
  direction, so its only authority is the team-auth signature;
- the human origin refuses any request carrying `Authorization`, `X-AWEB-*` or
  `X-AWID-*` (`403 team_auth_refused`);
- any other host is `421 unknown_origin`.

A route exists on one origin because it is declared in one of the two apps. The
lifespan is the agent app's.

## Approvals and passkeys

`aweb_naapp.runtime.approvals` is the single-use human approval primitive that
apps share. An agent proposes an exact request; any one of the owner-designated
humans eligible for it approves or rejects it; a trusted dispatcher then admits
exactly one dispatch of that exact request.

- **Frozen request.** `request_sha256` is SHA-256 over
  `aweb.approval-request/1\n` plus the canonical JSON of the request and its
  policy reference and version. Changing any covered value needs a new approval.
  `parse_request_json` refuses duplicate keys, floats and non-finite numbers.
- **Who decides.** A policy names its `approver_scopes`, and the app's
  `ApproverDirectory.candidates(policy, request)` returns the eligible
  approvers: one designated person each, never a group, role or shared subject.
  Mint freezes them as the approval's `candidates`, one per subject, without
  the requester unless the policy sets `allow_requester_approval`; with nobody
  left it refuses `no_eligible_approver`. The requester never chooses an
  approver, a contact or a delivery. The requester sees only `RequesterView`
  (`request_id`, state, delivery status, outcome): never a link, token or
  capability. The requester rule compares `requested_by` with each approver's
  subject and, when set, their `principal_did`, at mint and again at decide,
  so the app names the requester the same way.
- **One decision.** Any one candidate decides, and the first approve or reject
  is the only one: it is recorded as `decided_by` (scope, subject, assurance,
  evidence ref) and every other candidate's link is revoked. A failed ceremony
  consumes nothing.
- **Presentation.** A link presentation sends each candidate their own one-use
  link to their registered contact through the app's `ApprovalDelivery`; only
  its SHA-256 verifier is stored. A link is personal: it decides only for the
  candidate it was sent to, and a link no longer usable answers
  `link_unavailable` whatever the approval's state. Opening a link consumes
  nothing; a successful decision uses it. Under a passkey-minimum policy the
  request is shown only after a `view` assertion, which consumes nothing;
  otherwise, or when the policy sets `link_reveals_request`, link possession
  alone reveals the request. A task presentation names its candidate with
  `subject=`, and needs the app's `TaskAnswerVerifier` to verify the
  member-signed answer and its receipt, given by that candidate's
  `principal_did`; the authenticator proof is bound to that task answer, and
  the approval stays pending until both verify. Candidates without a principal
  are not eligible for a task presentation.
- **Assurance.** Each `ActionPolicy` sets a minimum of `member_session` or
  `passkey`. An `Authenticator` adapter derives the evidence from a verified
  proof; a caller cannot claim an assurance by naming it. The passkey adapter is
  below; `member_session` is an adapter seam for apps that have member sessions.
  Every proof is bound by `challenge_binding` to one approval, candidate,
  purpose (approve, reject or view) and task answer.
- **Current approver.** A decision is only as good as its approver's current
  designation: challenge and decide refuse a candidate with `approver_retired`
  once the `ApproverDirectory` no longer names them or they were retired, and
  with `no_eligible_approver` once no candidate is left; admit refuses an
  approval whose decider is no longer current. Retiring an approver takes them
  off pending approvals, with their links, and revokes the approvals they
  decided that are not yet dispatched.
- **Admission.** `admit()` is a compare-and-set under a row lock and a lock per
  request digest. A retry under the same operation ID retrieves the admission
  and is not a new dispatch; after `not_sent` it allows a transport retry while
  the approval is unexpired and unrevoked. The outcome lives on the consumption:
  `dispatching → completed | not_sent | outcome_unknown`, and the owner
  reconciles `outcome_unknown`. While a dispatch of the same request digest is
  dispatching or unknown, no other approval of it is admitted. No outcome rearms
  an approval.
- **Transactions.** `mint`, `decide`, `admit`, `record_outcome`, `reconcile`,
  `revoke` and `revoke_many` take an optional pgdbm transaction from the same
  database, so the change commits with the app's own writes. Minted in a
  transaction, an approval's links are not sent: `mint` returns a
  `PendingApproval`, which the app passes to `deliver` after the commit, so no
  link points at an approval that rolled back. Audit events go to the app's
  `AuditSink` inside the transaction of the change they record.
- **Storage.** `ApprovalStore` is the interface; `PgApprovalStore(db)` keeps
  the records in the app's own pgdbm schema, and `migrate()` applies its
  migrations (module `aweb_naapp_approvals`).

`aweb_naapp.runtime.passkeys` verifies app-local WebAuthn passkeys with
[py_webauthn](https://github.com/duo-labs/py_webauthn), maintained by Duo Labs
since 2017. It does all of the WebAuthn cryptography and
parsing: attestation formats, COSE keys, signature and counter checks. Its
server-only API takes the expected challenge, relying party ID, origin and
user-verification requirement as explicit arguments, which this module binds to
the approval, decision, policy and the app's own origin.

- The relying party is the app's own origin (`RelyingParty`).
- `verify_registration(credential, challenge=..., rp=...)` and
  `verify_assertion(proof, challenge=..., rp=..., credential_id=...,
  public_key=..., sign_count=...)` are the stateless ceremony checks `Passkeys`
  uses, for any caller with its own challenges and credentials. They always
  require user verification and raise `WebAuthnRefused` on any failure.
  `verify_assertion` takes the stored credential the caller chose for the
  expected subject and refuses a proof naming any other credential, since the
  proof's credential ID is not signed. The caller makes each challenge
  single-use, stores the credential and advances its counter with a
  compare-and-set on `new_sign_count`.
- `designate(tx, scope=..., contact=..., evidence=...)` runs in the caller's
  transaction. The evidence is a `VerifiedOwnerAct`, which the owner-act
  verifier (`aweb_naapp.hooks.owner_act_nonces`) consumed in that same
  transaction: `app-role.designate` for a scope's first approver,
  `app-credential.recover` to replace one. The act names the scope, commits to
  the contact by hash and takes effect once. For a scope the app does not count
  as an owner scope (`Passkeys(owner_scopes=...)`, every scope by default), the
  evidence may instead be an `OwnerApproval` from `owner_approval()`: an owner's
  decided approval, admitted and completed through B2 in the same transaction.
  It designates only a scope's first approver. Whether the approved request asks
  for that designation is the app's check.
- Nothing is sent inside the transaction. After the commit the caller sends the
  enrolment link and any recovery notices with `deliver(designation)`. If that
  never happens, `reissue_enrolment(tx, scope=...)` revokes the unused link and
  issues a new one to the same contact, while the approver has not enrolled.
- The enrolment link goes only to the designated contact. Whoever first
  completes enrolment through the link registers the passkey: this is **trust
  on first use**, and the audit event records it as such. The link is as strong
  as the contact channel it travels through.
- Recovery from a lockout retires the previous approver at once, with its
  passkeys, unused enrolment links and live approvals (through
  `ApprovalRevocation`, in the same transaction). The new approver takes effect
  after a cooling-off period (`LockoutPolicy`, at least 72 h), during which
  the scope has no approver, and every contact previously recorded for the
  scope is notified. `recovery_pending_until` tells the app to freeze its own
  widening changes meanwhile.
- `retire(tx, scope=..., evidence=...)` ends a scope's designation on an
  `app-role.revoke` act consumed in the same transaction, for instance when the
  owner role behind the scope is revoked. The act's `subject_ref` must name the
  approver retire finds current, so a recovery committed after the act was
  signed is never retired by it. The current approver, or a recovery's
  pending one, is retired with its passkeys, unused enrolment links and live
  approvals. The scope then has no approver: its next designation is a first
  one and enrols a new passkey, and the retired passkeys stay dead.
- **Lock order when withdrawing an approver's authority.** An app that
  withdraws authority (a role, a membership, an owner) does it in one
  transaction, in this order: any installation fence; the authority's own
  delete (for example the S5 role delete or team purge); then
  `ApprovalRevocation.approver_retired`, or `Passkeys.retire`, which calls it;
  then its other writes. A path that checks authority before acting on an
  approval takes locks in the same order: fence, authority hold, then the
  approval. Retiring approvals before removing the authority inverts that
  order and can deadlock with such a path.
- A contact change needs the approver's own passkey, takes effect after a delay
  (at least 24 h) and is notified to the old and the new contact. An owner can
  also schedule one through an owner-confirmed change, with
  `change_contact_by_owner(tx, scope=..., new_contact=..., evidence=...)` on an
  `OwnerApproval` admitted in that transaction. The delay and notices are the
  same, and the notices go out with `send_notices` after the commit. It
  changes the contact only: no passkey is enrolled at the new contact without
  a recovery. The last owner's own contact is refused (`last_owner_protected`).
  Only one change may be pending at a time (`contact_change_pending`). The
  approver cancels a pending change from either path with their own passkey
  (`contact_cancel_options`, `cancel_pending_contact`), and the cancel wins.
- A new contact counts only once its holder proves it. Every contact change,
  from either path, sends a single-use proof to the new contact alone, through
  `PasskeyDelivery.deliver_contact_proof`, bound to that contact's digest. The
  holder confirms it with `prove_contact(token)` before the change's time; a
  change still unproven by then lapses, and the old contact stays. A contact
  given at designation is proven by the enrolment completed through it. So an
  approver's effective contact is always a proven one, which is what the owner
  count behind `last_owner_protected` relies on. Security notices, such as recovery
  notices, go only to proven contacts; the one message an unproven pending
  contact receives is its own proof.
- These durations are floors. App or owner policy may lengthen them, and
  deploy configuration may raise the floor itself (`lockout_floor`); nothing
  can go below 72 h and 24 h.
- Assertions are bound to one approval, purpose, task answer, request digest
  and policy version through `challenge_binding`. They need user verification, are
  single-use, and the authenticator counter must advance.
- Designation is the owner's attestation of one natural person. The primitive
  cannot detect sharing: a passkey or contact that several people share makes
  every approval attributable only to the group. Every `Authenticator` must
  likewise refuse non-individual principals; a `member_session` adapter needs a
  per-member principal from the identity layer or a custody attestation.
- `login_options(scope)` / `verify_login(scope, proof)` log in a scope's
  in-effect approver under the same rules, returning `PasskeyLogin(subject,
  contact, evidence_ref)`. What a login opens (a console or reader session) is
  the caller's. Roles are named scopes, such as `secrets.owner`, each designated
  through a team owner act.
- A passkey proves that an app-local human holds the enrolled authenticator. It
  is not AWID membership, team identity or key custody.
