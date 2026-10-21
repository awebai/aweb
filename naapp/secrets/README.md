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
