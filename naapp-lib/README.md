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

### Hook resolution

`aweb_naapp.runtime.hook_resolver.HookResolver` asks a team's coordination
server where to deliver its hook events (`registrations`), whom it accepts them
from and with which keys (`productions`), its own bindings in every state
(`own_bindings`), and the server's core producer keys (`core_producer_keys`).
It signs with the app's `hook-resolve` key and reaches only the server the
team's AWID `aweb.team-server/1` record names. Answers are reused for at most
60 seconds and never past their freshness. Every failure raises
`HookResolutionUnavailable`, except a missing complementary binding, which
raises `HookBindingRequired`. A binding is listed while active, including
before its `active_from`, which the caller compares with an event's
`occurred_at`. The server's side is described in `docs/app-registry.md`.

## Approvals and passkeys

`aweb_naapp.runtime.approvals` is the single-use human approval primitive that
apps share. An agent proposes an exact request; the owner-designated human
approves or rejects it; a trusted dispatcher then admits exactly one dispatch of
that exact request.

- **Frozen request.** `request_sha256` is SHA-256 over
  `aweb.approval-request/1\n` plus the canonical JSON of the request and its
  policy reference and version. Changing any covered value needs a new approval.
  `parse_request_json` refuses duplicate keys, floats and non-finite numbers.
- **Who decides.** The app's `ApproverDirectory` names the owner-designated
  approver for the policy; the requester never chooses the approver, the
  contact or the delivery. The requester sees only `RequesterView`
  (`request_id`, state, delivery status, outcome): never a link, token or
  capability.
- **Presentation.** A link presentation sends a one-use link to the approver's
  registered contact through the app's `ApprovalDelivery`; only its SHA-256
  verifier is stored. The link only locates the request. Opening it consumes
  nothing; a successful decision uses it. Under a passkey-minimum policy the
  request is shown only after a `view` assertion, which consumes nothing;
  otherwise, or when the policy sets `link_reveals_request`, link possession
  alone reveals the request. A task presentation needs the app's
  `TaskAnswerVerifier` to verify the member-signed answer and its receipt, and
  the authenticator proof is bound to that task answer; the approval stays
  pending until both verify.
- **Assurance.** Each `ActionPolicy` sets a minimum of `member_session` or
  `passkey`. An `Authenticator` adapter derives the evidence from a verified
  proof; a caller cannot claim an assurance by naming it. The passkey adapter is
  below; `member_session` is an adapter seam for apps that have member sessions.
  Every proof is bound by `challenge_binding` to one approval, purpose
  (approve, reject or view) and task answer.
- **Current approver.** An approval is only as good as its approver's current
  designation: challenge, decide and admit refuse with `approver_retired` once
  the `ApproverDirectory` no longer names the approver.
- **Admission.** `admit()` is a compare-and-set under a row lock and a lock per
  request digest. A retry under the same operation ID retrieves the admission
  and is not a new dispatch; after `not_sent` it allows a transport retry while
  the approval is unexpired and unrevoked. The outcome lives on the consumption:
  `dispatching → completed | not_sent | outcome_unknown`, and the owner
  reconciles `outcome_unknown`. While a dispatch of the same request digest is
  dispatching or unknown, no other approval of it is admitted. No outcome rearms
  an approval.
- **Transactions.** `decide`, `admit`, `record_outcome`, `reconcile`, `revoke`
  and `revoke_many` take an optional pgdbm transaction from the same database,
  so the change commits with the app's own writes. Audit events go to the app's
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
- Only a verified team owner act designates (`designate(owner_act=...)`):
  `app-role.designate` for a scope's first approver, `app-credential.recover`
  to replace one. The act names the scope, commits to the contact by hash and
  is used once. `OwnerActEvidence` is the seam the owner-act verifier fills.
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
- A contact change needs the approver's own passkey, takes effect after a delay
  (at least 24 h) and is notified to the old and the new contact.
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
  through the same owner act.
- A passkey proves that an app-local human holds the enrolled authenticator. It
  is not AWID membership, team identity or key custody.
