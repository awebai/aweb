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
all three keys with the shared K0 key-file format: a 32-byte Ed25519 seed as
64 hex characters with an optional trailing newline. Files must be regular
files and must not be group- or world-writable; symlinks to regular files are
supported. Read permissions are left to the deployment platform. For example:

```text
SECRETS_APP_KEY_FILES={"secrets:hook-event-1":"/run/keys/hook-event","secrets:hook-delivery-1":"/run/keys/hook-delivery","secrets:grant-read-1":"/run/keys/grant-read"}
```

The keys sign hook content, hook delivery and team grant reads respectively.
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
