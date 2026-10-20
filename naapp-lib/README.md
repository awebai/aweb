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
  verifier is stored. Opening it consumes nothing; a successful decision uses it.
  A task presentation records the task answer reference with the decision.
- **Assurance.** Each `ActionPolicy` sets a minimum of `member_session` or
  `passkey`. An `Authenticator` adapter derives the evidence from a verified
  proof; a caller cannot claim an assurance by naming it. The passkey adapter is
  below; `member_session` is an adapter seam for apps that have member sessions.
- **Admission.** `admit()` is a compare-and-set under a row lock and a lock per
  request digest. A retry under the same operation ID retrieves the admission
  and is not a new dispatch. The outcome lives on the consumption:
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
- The owner designates the approver for a scope and registers the approver's
  contact (`designate`). The enrolment link goes only to that contact. Whoever
  first completes enrolment through the link registers the passkey: this is
  **trust on first use**, and the audit event records it as such. The link is
  as strong as the contact channel it travels through.
- Recovery from a lost device is the owner designating the approver again,
  which retires the previous approver's passkeys and unused enrolment links.
  Approvals already approved stay admissible; revoke them with `revoke_many` if
  that is wrong for the app.
- Assertions are bound to one approval, decision, request digest and policy
  version through `challenge_binding`. They need user verification, are
  single-use, and the authenticator counter must advance.
- A passkey proves that an app-local human holds the enrolled authenticator. It
  is not AWID membership, team identity or key custody.
