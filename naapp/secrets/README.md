# secrets

The secrets naapp lets AWID team members use credentials without holding them:
it brokers requests and runner jobs under owner-defined grants and policy, and
records every use. The design is `docs/design/secrets.md`; the build plan is
`docs/design/secrets-build-plan.md`.

The service (`aweb_secrets.app.create_app`) runs on the shared naapp runtime,
`aweb_naapp`, as one process on two origins:

- **The agent API origin** (`SECRETS_PUBLIC_ORIGIN`) serves the manifest
  (catalog `/.well-known/aweb-app-versions.json`, variant `/manifests/v2.json`,
  also `/aweb-app.json`), health and the manifest's tools. Every tool is
  admitted only through team-auth: signed by a member, declared by the manifest,
  covered by the team's installed grant and allowed by secrets' policy. This
  origin never reads or sets a cookie.
- **The console origin** (`SECRETS_CONSOLE_ORIGIN`) serves people in a browser.
  It refuses any request carrying team-auth, and serves no tool.

No tool reads, sets or exports a secret value. `/health` and `/ready` report the
build commit (`SECRETS_GIT_SHA`, or Render's), the database, the KMS canary and
the age of the oldest undelivered outbox event. `/ready` is 503 while any of
them fails. The database is the app's own pgdbm schema: the shared runtime's
migrations first, then `src/aweb_secrets/migrations/` (module `aweb_secrets`).

The manifest's authoring source is `src/aweb_secrets/manifest.py`. The committed
`aweb-app.json` is a canonical v2 template. The shared runtime fills the served
`app.id` from `SECRETS_APP_ID`, the origin from `SECRETS_PUBLIC_ORIGIN`, and each
`app_keys` entry's `did_key` from `SECRETS_APP_KEY_FILES`. The template fixes each
kid and its purposes; it contains no signing key or deployment did:key. Configure
all four keys with the shared K0 key-file format: a 32-byte Ed25519 seed as
64 hex characters with an optional trailing newline. Files must be regular
files and must not be group- or world-writable; symlinks to regular files are
supported. Read permissions are left to the deployment platform. For example:

```text
SECRETS_APP_KEY_FILES={"secrets:hook-event-1":"/run/keys/hook-event","secrets:hook-delivery-1":"/run/keys/hook-delivery","secrets:grant-read-1":"/run/keys/grant-read","secrets:hook-resolve-1":"/run/keys/hook-resolve"}
```

The keys sign hook content, hook delivery, team grant reads and hook resolution
respectively. Hook resolution uses its dedicated purpose through the shared
runtime resolver; an event or delivery key cannot substitute for it.
A declared key without a file, an undeclared configured kid or an invalid key
stops startup. Hook production still needs owner activation; declaring it grants
no authority. Every tool requires team-auth. `propose-change` and `activity` are
surface-only; the other seven tools serve agents and surfaces. Widening drafts
still require the console passkey confirmation, and no tool accepts a value.

A reachable self-hosted deployment must set its own stable `SECRETS_APP_ID` and
origin. The hosted identity `secrets` is valid only at its hosted origin or a
loopback development origin. Choose that ID before installing: changing it later
creates a different app identity and orphans existing installations; it does not
rename or migrate them.

### Public surfaces

`aweb_secrets.surfaces` supplies the landing, `/reference`, `/llms.txt` and
packaged agent skills on the shared `aweb_naapp` design system and chrome. The
reference and operation blocks use the runtime's resolved manifest, including
the deployment's app id. Fonts, social card and skills ship in the package.
`SECRETS_SKILLS_DIR` can override the packaged skills directory.

The composition owner replaces the API app's separate manifest and health
mounts with `mount_public_surfaces(api, runtime=runtime, health_checks=checks, console_origin=settings.console_origin)`,
where `checks` is the complete existing mapping (runtime checks plus KMS).
The helper serves only public documentation/assets and the runtime's unchanged
manifest and health routes. Mount it only on the public API app; the separate
passkey console keeps its own health routes and CSP.

The console origin is explicit: its root is the reviewed console shell's
setup/sign-in entry. Public links carry no authority. Publishing the landing
depends on mounting that shell and the owner's content/forms on the human app.

Landing wording is copy v1 approved by Juan on 2026-10-21. Its read-back promise
is about app interfaces: the service handles transient plaintext, and the vault
and runner host retain their documented trust boundaries (§14 of the design).

Tests compare the filled served bytes against the shared canonical filler and
load them with the X8/C3 interpreter. The shared conformance inputs are
`test-vectors/app-manifests/app-manifest-v2-v1.json` and
`test-vectors/app-manifests/app-manifest-discovery-v1.json`; their harness is
`naapp-lib/tests/test_manifest_v2_vectors.py`.

This package also holds secrets' own contract vectors (`vectors/`) and the
tests that consume them (`tests/`). The runner protocol is a public interop
contract, so its vector lives with the other public vectors in the repository's
`docs/vectors/`.

```bash
uv sync
make lint
make test
```

The tests need PostgreSQL, as pgdbm's test fixtures configure it.

Custody ingests structured values using `encode_value(kind, fields)`; the broker
uses `decode_value(kind, opened.reveal())`. Both live in `aweb_secrets.custody`
and share the fields in `operation.CAPTURE_FIELDS`. Decode failures carry no
value bytes. The stored payload is UTF-8 JSON; callers never log it.

Apply the app's record migrations before custody migrations. Existing-secret
ingest locks and re-reads its secret record before validating and sealing. A
first-create draft passes its candidate as `initial=record`, since the record
is created only at confirmation. Once any value has been sealed, the kind,
backend and parameters controlling where it goes are fixed, even if all value
versions are destroyed. OAuth scope and descriptions remain editable. Both draft
and confirmation refuse a reshape; confirmation serializes with ingest under the
parent-then-custody lock order documented in `custody.store`.

The human app can mount owner value ingress alongside the shared console:

```python
from aweb_secrets.console_values import ConsoleValues, console_values_router

human_app.include_router(
    console_values_router(ConsoleValues(console=owner_console, custody=custody))
)
```

`POST /installations/{installation_id}/backend-credentials/onepassword/versions`
accepts a JSON object with one `value` string and the current tab's
`X-CSRF-Token`. It uses the authoritative installation lookup, current owner
role and exact live login evidence, then seals the token through native custody.
The no-store response is the inert `backend_credential/1` after record
(`v`, `backend`, `credential_id`, `version`). Activation belongs to the existing
fresh passkey-approved `ChangeSets.confirm` flow. Keep this router on the human
origin; entered bytes and response bodies must never be logged or stored in
browser storage. Customers enter their own team's token; composition provides
no operator token loader.

`POST /installations/{installation_id}/onepassword/references` accepts
`secret` (the complete secret record v1 with backend `onepassword`), `reference`
(`vault_id`, `item_id`, and logical-field-to-field-ID `fields`), and a positive
integer `credential_version`, with the same owner session and tab CSRF. After
owner authorization, it opens the scoped staged or active token and reads the
item through the official SDK outside authority transactions. A new transaction
rechecks F6, the owner role, the exact LOGIN evidence, the open session and the
scoped token/actual secret shape before staging metadata. The no-store response
is the inert `onepassword_binding/1` after record; it never includes item values
or the token. Staging creates no active secret or binding. Secret/binding
confirmation shares the canonical change-set routes: create the secret record,
activate the staged binding and, when needed, activate its staged backend token
in one owner-confirmed change. The reference form described below uses a
previously confirmed active backend token. Successful external vault access
still requires the HO6 fixture and release proof.

`aweb_secrets.approval_email.ApprovalEmailDelivery` implements B2 delivery for
both use and change approvals. Composition supplies a shared
`aweb_naapp.email.Mailer` and the trusted absolute console endpoint:

```python
delivery = ApprovalEmailDelivery(mailer=mailer, approval_url=console_origin + "/approvals")
```

Send through `Approvals.deliver(pending)` after the minting transaction commits.
Each designated approver receives only a static notice and its own locator, with
the opaque token URL-encoded in `#token=...`; no request details go in email.
The console posts that token in JSON to its B2 ceremonies and requires a passkey
to show the frozen request and decide. SMTP failures return `FAILED` without an
automatic retry. The shared sender reads `SECRETS_EMAIL_*` configuration and its
password file through `EmailSettings.from_env("SECRETS_")`.

Use approvals resolve coverage through `derived_lineage.ancestry_ids`: an
ancestor's approver is eligible only when the child's policy also lists it.
`request_use_approval` and `admit_approved_use` take the current deployment cap
as `max_ttl_s` (default 3600). The caller holds the installation fence and any
role hold first; these functions then lock ancestry root to leaf, grants in
ascending order, covering approver records, and B2 approvals. Coverage and
ancestor authority are rechecked before first sends and `NOT_SENT` retries;
already admitted dispatches remain retrievable without authorizing another send.
Expiry is checked again after blocking coverage/approval reads, before mint
commits or a new send is admitted.
B2 admission runs in a savepoint and ancestry expiry is checked after B2's own
asynchronous reads and writes. An expired result rolls back tentative consumption,
outcome and audit writes, then voids the approval in the caller's transaction.

Containment calls `revoke_use_approvals(tx, approvals, installation_id=...,
team_id=..., secret_ids=descendant_ids, revoked_by=..., reason=...)` in the same
fenced transaction as the grant revocation and descendant state changes. The
caller supplies the exact descendant IDs from stored lineage. The selector
uses the existing scoped approval registry and leaves other siblings untouched.
Pass `source_grant_id=revoked_grant_id` to include direct approvals admitted
under that exact source grant in the same sorted B2 revocation union. It joins
the intent in the same installation/team; direct approvals under other grants
remain untouched. Omit it for the existing exact-secret, all-version selection.
`void_use_approvals` remains the version-replacement operation.

The fresh-confirmation HTTP routes support `create` items for backend credentials,
1Password bindings, secret metadata/native values, destinations, operations,
grants, policies, plain roles, jobs and runners. Every such effect requires the
actual retained APPROVE commitment and atomic signed governance recording.
Job credentials must name same-installation/team secrets and compatible structured
fields; this slice supports durable slots. Job updates, mint slots and B3
approver/contact changes retain their integration guards.
Mount it only on the human application, sharing the same services:

```python
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router

console_changes = ConsoleChanges(
    console=owner_console,
    changes=change_sets,
    approvals=approvals,
    registrations=hook_registrations,
    after_commit=containment.evict,
)
human_app.include_router(console_changes_router(console_changes))
```

Authenticated POSTs require JSON, the S4 cookie and this tab's `X-CSRF-Token`. Browser
forms call `window.awebSecretsConsole.post(path, body)`. Under
`/installations/{installation_id}/change-sets`:

- `POST` takes exactly `{changes, sealed, reason}`. `changes` uses existing
  change/1 items; `sealed` contains `{secret_id, version}` locators from ingress.
  The server supplies the installation/team/generation, authenticated drafter,
  current revision, random change ID and ten-minute lifetime. The response is
  `{change_id, approval_id, state: "pending"}`, with no approval link or value.
  Registered-contact delivery runs after the draft commits.
- `GET /{change_id}` returns the persisted frozen change to an owner of this
  installation, for rendering; it does not rebuild it from current records.
- `POST /{change_id}/approval-options` takes `{token}` from the registered
  contact's locator link and returns B2/B3's fresh APPROVE options.
- `POST /{change_id}/approve` takes `{token, assertion}` and records the fresh
  passkey decision. The logged-in owner must be that link's candidate.
- `POST /{change_id}/confirm` takes `{}`. Only the deciding owner's current
  session can consume the retained approval through `ChangeSets.confirm`.
  The trusted governance registration view is fetched before authority locks;
  required outbox recording and activation share the confirmation transaction.

The protected confirmation response uses `owner_confirmation_result`; serve
it with no-store and never log its body. Eviction receives only the committed
Confirmation's installation/team/affected IDs, after commit. A cleanup failure
never repeats confirmation; active-version and custody checks remain the
release controls. If the session is lost after commit, the response contains
only `{change_id, revision, state: "applied", reauth_required: true}` and any
clearing-cookie header; it carries no protected material and does not report a
rolled-back mutation.

The effect is authorized by the retained fresh APPROVE, with S4 checking the
exact login on request entry. It takes no late LOGIN credential lock after the
forest/B2 locks. Within a valid session, possession of that session and its CSRF
token can apply the exact change its real owner has already approved; it cannot
supply the fresh passkey proof needed to approve another change.

Mount the browser forms with the same services, only on the human application:

```python
from aweb_secrets.console_forms import console_forms_router
human_app.include_router(console_forms_router(changes=console_changes))
```

`GET /backend-credentials/onepassword/new` resolves the installation from the
stored owner scope and renders token entry through the shared console shell.
The field clears as soon as submitted, and no token enters a URL, template or
browser storage. Saving stages an inert token and drafts its metadata. The
page directs the owner to the registered-contact approval link.

`GET /secrets/new` and `/onepassword/references/new` render reference entry;
`/installations/{installation_id}/onepassword/references/new` is the scoped
equivalent. The page requires the current owner session and role, resolves the
active backend version for that exact installation and team, and offers the
connection page if none is confirmed. No credential version is entered by the
owner. Labelled controls collect secret metadata, authentication parameters,
and vault/item/field IDs for each supported authentication kind, never vault
field values. The browser submits the existing metadata ingress, then drafts
`secret/create` and `onepassword_binding/create` with the returned inert version
through the sole writer and navigates to canonical review. It stores no form
data, retries no mutation automatically, and cannot activate a binding without
fresh approval and confirmation. The form's successful external SDK path is
part of the real-root/HO6 journey; local refusal tests do not replace that proof.

`GET /approvals#token=<locator>` accepts the personal email fragment. With no
session, the public read-only `POST /approvals/sign-in` accepts exactly `{token}`
and returns only that link candidate's opaque sign-in scope. This neither
reveals the frozen change nor authorizes anything. The page calls the existing
S4 login APIs with a real LOGIN assertion, stores only the tab CSRF, then loads
the authenticated review. It still needs a separate fresh APPROVE assertion.
`POST /approvals/locate` is authenticated and CSRF-protected; it resolves the
same candidate's link to the scoped frozen change. Locators stay transient and
are removed from the fragment immediately; they never enter browser storage.

The review renders persisted frozen metadata with escaped untrusted reason
text. `/installations/{installation_id}/change-sets/{change_id}/review` also
lets a deciding owner resume an approved change after a page reload, without
approving again. Browser actions use the sole shared `post` and `assertion`
helpers; no automatic mutation retry occurs. New tabs without tab CSRF retain
the shared scoped re-authentication guard. Frozen review shows every proposed
field. A runner registration code appears once in that deciding document after
commit; it is never stored for a later read, navigation or retry. Other
configuration entry forms and the real root application mount remain separate
integration work.

Run-slot approvals use the same B2 service and `apply_use_approval_migrations`.
`run_approvals.request_run_approvals(tx, approvals, prepared=..., principal=...,
reason=...)` accepts only the internal planner's `PreparedRun`. The planner
already holds installation, requester roles, full ancestry/grant unions and
CURRENT runner/job/operation/template locks. S12 locks one sorted covering-record
union for the run, intersects parent/template policy scopes per slot, and mints
one approval for each required slot. The signed use-approval/1 `run_job` keeps
exactly its existing five fields. After authorizing the B2 ceremony, the console
calls `run_approval_view(tx, installation_id=..., team_id=..., approval_id=...)`
to read the complete plan, original ordinal, actual mapped issuer values and
complete child grant authority from that approval's immutable same-scope
plan/slot association. No live definition or caller-supplied plan enriches the
view. Only new results have `pending`; deliver those after commit.
A repeated request returns the same B2 refs with `pending=None`.

`admit_run_approvals(tx, approvals, prepared=...)` consumes every required B2
approval under the original run dispatch ID inside one savepoint. Any pending,
denied or stale slot refuses the joint admission. After all awaited work and the
joint marker write, it runs the live prepared recheck and frozen approval expiry
check; refusal rolls back consumption, outcome, audit and marker together.
No-approval runs still get the final recheck and one admission marker. Once that
marker commits, retrieval returns `may_send=False`; an internal mint or retry ID
cannot reconsume B2 or rearm this marker.

The result and read-only `run_approval_record(tx, installation_id=..., team_id=...,
run_id=...)` expose original run/intent/dispatch IDs, plan digest and ordered
slot/B2 refs. The frozen plan, all slot associations and joint marker are
immutable. These records are inert: S13 verifies the same-scope persisted match
inside its transaction before constructing `AdmittedRun`, and owns execution,
CURRENT/forest/role rechecks and the mint/child mapping. Job and issuance
availability guards remain closed.

Containment's `select_use_approval_ids(tx, installation_id=..., team_id=...,
secret_ids=...)` reads sorted distinct B2 IDs across ordinary uses and run slots,
all versions and states. Union confirmation IDs and call `Approvals.lock_many`
once before any callback/consumption. `use_approval_secret_ids(tx, ...,
approval_id=...)` resolves the exact scoped source targets of an approval for
application authorization; a full frozen-plan view gives no action coverage over
other slots. Unknown/out-of-scope targets and empty/no-B2 plans return empty
results. The existing scoped `void_use_approvals` and `revoke_use_approvals`
selectors include run slots in the same single B2 revocation union.
