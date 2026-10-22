# Folio production operations

Production actions (deploys, service setting changes, rollbacks) are taken by
the hosted operator on an explicit go. This document states what the build
needs; it grants no authority to act.

## Build

Folio depends on the awid and naapp-lib of the aweb checkout it lives in
(`[tool.uv.sources]` in `pyproject.toml` names `../../awid` and
`../../naapp-lib`). The Docker build therefore needs the **repository root** as
its context; a context of `naapp/folio` cannot see those directories.

```sh
docker build -f naapp/folio/Dockerfile .    # from the aweb repository root
```

The Dockerfile copies only the paths the service needs (`awid/`,
`naapp-lib/`, and folio's `pyproject.toml`, `uv.lock`, `README.md`, `src/` and
`skills/`). Those trees are copied whole, so `naapp/folio/Dockerfile.dockerignore`
is what keeps files local to a checkout out of the build context and the image:
`.env` files, virtualenvs, bytecode, tool caches, `.aw` identity homes (aw's
signing key, encryption keys and team certificates), and `*.key` and `*.pem`
files. `/app` mirrors the
repository layout (`/app/naapp/folio`, `/app/awid`, `/app/naapp-lib`), so the
path sources resolve in the image as they do in a checkout.

### Hosting service settings

A web service that builds Folio with Docker needs:

| Setting | Value |
| --- | --- |
| Repository | `github.com/awebai/aweb`, branch `main` |
| Root directory | the repository root (empty) |
| Dockerfile path | `naapp/folio/Dockerfile` |
| Docker build context | `.` (the repository root) |
| Health check path | `/health` |

A root directory of `naapp/folio` limits the build to that folder, which is why
the root directory moves to the repository root. Whether a given host resolves
the Dockerfile path and context relative to the root directory or to the
repository is host behaviour; confirm it against the host's settings before the
first build.

If the service redeploys automatically on commits, scope its build filter to
`naapp/folio/**`, `naapp-lib/**` and `awid/**`, since a change to any of them
changes the image.

### Moving an existing service onto this build

The settings change and the first deploy of a commit with this Dockerfile go
together:

1. Before the change, a build of any commit with this Dockerfile under a
   `naapp/folio` root directory fails at the first `COPY awid/...`. A failed
   build does not replace the running deploy.
2. After the change, a build of an older commit whose Dockerfile expects the
   `naapp/folio` context fails the same way. Rolling back across this change
   therefore means restoring the old settings with the old commit, unless the
   host rolls back by reusing the earlier built image.
3. Verify the new deploy with `GET /health` and an authenticated read, which
   exercises team-certificate verification through the in-repo awid.

## Pinned production service

`ops/render-production.json` pins the live service: its Render service ID,
name, region, repository, branch, root directory, Dockerfile path, Docker
context, origin and public URLs, and health path. `render.yaml` is only a
template for a fresh deployment and is not the production identity; its build
fields must match the manifest, which a test enforces.

The manifest describes the build in the table above. Until the service's
settings move to that build, `make prod-status` fails closed and names each
setting that differs, so the move is visible before it is made.

## Operations

All production operations go through Make and the shared `aweb_naapp.ops`
tool. Each one first checks the live service against the manifest and refuses
on any difference. It also refuses unless the service is not suspended and its
auto-deploy is off: the service builds from `main` of the aweb repository, so
with auto-deploy on every push to `main` would redeploy Folio outside these
targets. The tool requires both for every service; they are not manifest
settings.

| Target | Effect | Inputs |
| --- | --- | --- |
| `make prod-status` | read only: the pinned service and its live deploy | `RENDER_ENV_FILE` |
| `make prod-deploy` | deploys one commit, which must be the tip of `main` on the remote, while the named deploy is live | `PROD_COMMIT`, `ROLLBACK_DEPLOY_ID`, `ROLLBACK_COMMIT`, `APPLY=1`, `CONFIRM_SERVICE_ID` |
| `make prod-wait` | waits for a deploy to go live | `PROD_DEPLOY_ID`, `PROD_COMMIT` |
| `make prod-verify` | read only: the deploy is live with that commit and health answers on both URLs | `PROD_DEPLOY_ID`, `PROD_COMMIT` |
| `make prod-rollback` | redeploys an earlier deploy's built artifact | `ROLLBACK_DEPLOY_ID`, `ROLLBACK_COMMIT`, `CURRENT_DEPLOY_ID`, `CURRENT_COMMIT`, `APPLY=1`, `CONFIRM_SERVICE_ID` |

`RENDER_ENV_FILE` (default `~/.aweb-render/env`) holds `RENDER_API_KEY` and
must be readable only by its owner.

Rollback never deploys a commit: a commit deploy rebuilds under the service's
current settings, which for a commit from before the repository-root build
fails. Rolling back across that change uses the earlier deploy's artifact.

The deployed commit is read from the Render API and Folio's shared `/health`
build identity (`RENDER_GIT_COMMIT`, with `FOLIO_GIT_SHA` as a fallback).


## Filled manifest and emit-key configuration

The committed `src/folio/aweb-app.json` is a template. It declares the stable
`folio:emit-1` kid and local event type `doc.changed`; the shared runtime fills
its public did:key from configuration before serving either manifest URL.
Keep the production app id `folio` (`FOLIO_APP_ID`), kid and
`FOLIO_PUBLIC_ORIGIN=https://folio.aweb.ai` unchanged. App id is stable for the
entire deployment lifetime: changing it orphans installed grants.

The existing `FOLIO_APP_EMIT_KID=folio:emit-1` and secret
`FOLIO_APP_EMIT_KEY_SEED_HEX`, together with `FOLIO_APP_EVENTS_ORIGIN`, remain
sufficient. No new emit-key environment variable is required. Alternatively,
`FOLIO_APP_KEY_FILES` is a JSON map from each declared kid to a mounted signing-key
file; do not configure both a file and a seed for the same kid. Every declared
kid requires a configured key even when outbound event delivery is disabled.
Never place a production seed or private key in the committed template.

The template's local event declaration changes the manifest digest. Emitted
event bodies, subscriptions and stream wakes still use `folio/doc.changed`:
the server matches that namespace against installed app `folio` and local type
`doc.changed`. The redeploy handoff must include updating **every existing
Folio install** to the new digest immediately after deploy, through
`aw plugin update folio` or the install API. Until an install is updated, the
hosted MCP offers no Folio tools for that team. Key rotation likewise adds a
new declared kid beside the old one, yields a new digest, and needs a re-pin.
These are separately authorized operator actions; a code landing performs none
of them.

## Records and live collection tables

Before deploying the records build, provision a **separate database** for the
shared deletion ledger. It must not be the content database under another schema.
Configure these exact environment names:

- `AWEB_PAGE_DELETION_DATABASE_URL`: the deletion-ledger PostgreSQL DSN.
- `AWEB_PAGE_RETENTION_POLICY`: JSON with the approved policy below, including
  its explicit version and legal-exceptions list.
- `FOLIO_APP_KEY_FILES`: JSON mapping `folio:grant-read-1` to a mounted,
  owner-readable signing-key file. This key has purpose `app-grant-read` only.
  It is separate from `folio:emit-1` and its existing emit seed. A missing grant
  key refuses startup; the emit seed cannot substitute for it.

Juan's approved 2026-10-20 retention values are:

```json
{"version":"2026-10-20","content_purge_days":7,"audit_content_days":90,"backup_expiry_days":30,"backup_interval_hours":24,"restore_rpo_hours":24,"retry_horizon_days":30,"encrypted_backups":true,"legal_exceptions":[]}
```

The runtime applies the shared stores' migrations before serving requests, starts
restore fencing and runs retention maintenance. Missing ledger configuration
leaves record operations unavailable; a missing retention policy prevents content
writes. Backups must satisfy the configured encrypted-backup, expiry and RPO
requirements; the policy declaration alone does not provision them.

Records uses manifest v2. Install by the app origin so discovery follows
`/.well-known/aweb-app-versions.json` to `/manifests/v2.json`; `/aweb-app.json`
serves the same filled bytes. There is no v1 document at the legacy well-known
path. The records tools and grant key change the manifest digest, so coordinate
an immediate pin update for every existing install after the separately approved
deploy. Existing agent identities remain unchanged.

The coordination server must supply a real installation ID and generation (F6).
Folio refuses a missing identity; it never allocates either value. The shared
TeamGrantSource uses Folio's filled manifest digest and the runtime's one
TeamServerDirectory. Records traffic must not be enabled ahead of that server
cutover. No deploy, key provisioning or install update is performed by landing
this code.


## Editable presentation privacy and expiry

Editable presentation links default to 300 seconds. The server refuses an
explicit editable TTL above 300 seconds; read-only TTL settings are unchanged.
An editable row minted by an older build with an expiry more than 300 seconds
after its creation is refused on the editor, state, preview and save paths.
This requires no migration or inspection of production document rows.

After an expired or revoked save, the editor keeps the unsaved textarea and
provides a copy action with instructions to return to the dashboard, reopen
Edit and paste the draft. It never retries a failed save automatically.

Every `/present/` response, including expected refusals, carries
`Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Folio installs its
access-log filter when constructing the app, including under the Dockerfile's
standard Uvicorn command. The filter redacts legacy capability-token path
segments and suppresses query strings on all access records, including records
queries whose `bind` values may be private. It changes only log records, never
the URL used for routing or signature verification. Upstream access logs must
follow the same redaction policy; the Folio filter operates on Folio's own logs.

Focused local proof (requires PostgreSQL, `uv sync` and the Chromium matching
`uv run playwright install chromium`; run under the team's suite lock):

```sh
uv run pytest -q tests/test_present_privacy.py tests/test_editor_browser.py
FOLIO_EDIT_REAL_EXPIRY=1 uv run pytest -q tests/test_editor_browser.py -k expired
```

The second command keeps a real editor open for more than 300 wall-clock
seconds, then saves through the production route and SQL to assert refusal,
copyable retained text and no appended version. The normal regression ages
only disposable test rows for fast coverage of the same failure path. These
checks seed a synthetic document in real PostgreSQL; they do not claim the
separate dashboard mint/authentication flow or a deployed production pass.
