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
team-auth verifier, approvals, passkeys) lives under `aweb_naapp.runtime` and
needs the `runtime` extra: `aweb-naapp[runtime]`.

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
  through a team owner act.
- A passkey proves that an app-local human holds the enrolled authenticator. It
  is not AWID membership, team identity or key custody.
