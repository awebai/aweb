# secrets

The secrets naapp lets AWID team members use credentials without holding them:
it brokers requests and runner jobs under owner-defined grants and policy, and
records every use. The design is `docs/design/secrets.md`; the build plan is
`docs/design/secrets-build-plan.md`.

The service (`aweb_secrets.app.create_app`) runs on the shared naapp runtime,
`aweb_naapp`, as one process on two origins:

- **The agent API origin** (`SECRETS_PUBLIC_ORIGIN`) serves the manifest
  (`/.well-known/aweb-app.json`), health and the manifest's tools. Every tool is
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
`aweb-app.json` is its canonical bytes, and a test keeps the two equal.

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

Containment calls `revoke_use_approvals(tx, approvals, installation_id=...,
team_id=..., secret_ids=descendant_ids, revoked_by=..., reason=...)` in the same
fenced transaction as the grant revocation and descendant state changes. The
caller supplies the exact descendant IDs from stored lineage. The selector
uses the existing scoped approval registry and leaves other siblings untouched.
`void_use_approvals` remains the version-replacement operation.
