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

## Read-only presentation lifetimes

Read-only links accept up to 30 days (`2592000` seconds); the default lifetime
remains one day (`86400` seconds). Operators may set a shorter ceiling. An
explicit request above the configured ceiling returns `422` without minting a
link. Editable openers remain limited to 300 seconds; established edit sessions
have no expiry, as described below.

For the 30-day rollout, check the existing `FOLIO_MAX_PRESENT_TTL_SECONDS`
environment setting. If it is `604800` (the former seven-day example), raise it
to `2592000` or remove it to use the new default. Keeping that override preserves
the seven-day ceiling even after the code deploys. `.env.example` now uses
`2592000`. The committed app manifest and its tool schemas do not change, so
this lifetime change alone needs no manifest re-pin.

## Editable opener and session deployment

Apply forward Folio migration `002_edit_sessions.sql` during deployment. It adds
hashed opener/consumption/minter-key evidence and a persistent hashed edit-session
table. Initial migration 001 stays unchanged. No production document rows need
inspection. Read-only links retain their existing TTL and URL behavior.

Editable URLs now use `/present/edit/<public-id>#k=<opener>`. Their opener is
single-use and lasts at most 300 seconds; an already-open session never expires
on time or inactivity. Cloud's exact fragment-URL validation change must deploy
**before** this Folio build, or dashboard Edit will reject the new URL. Folio's
manifest bytes/digest remain unchanged, so this change needs no install re-pin.

Old editors still using token paths will enter draft-copy recovery on their next
request after deployment. There is no compatibility authority path. The person
copies their unsaved text and reopens Edit from the dashboard. A reload of a new
session works through its per-link sessionStorage credential; the database keeps
sessions across app restarts and instances.

Revoke the public link id to end a consumed opener's session. Document deletion,
minter removal, or replacement/revocation of the minter's certificate also ends
it. Certificate rotation therefore requires reopening Edit even when the person
remains a team member. AWID unavailability is a retryable 503, never authority.
The shared team-facts cache bounds membership freshness at 60 seconds. There is
no idle timeout or hard session lifetime under Juan's ruling.

Every `/present/` response, including exchange and refusals, carries no-store and
no-referrer. Neither the fragment opener nor session header reaches access paths.
Only SHA-256 verifiers reach the database. Folio's access filter also suppresses
all query strings and redacts old bearer path segments; errors must not log
request bodies or session headers. Upstream logging must follow the same policy.

Focused proof under the team suite lock:

```sh
uv run pytest -q tests/test_edit_sessions.py tests/test_editor_browser.py tests/test_live_refresh.py
```

The session tests use real disposable PostgreSQL/HTTP/Chromium and age only the
fixture opener to model a hidden tab returning beyond 300 seconds. The existing
Docker CLI/AWID journey covers actual member signing. The paired Cloud test
starts at Documents Edit and proves the fragment survives backend validation and
popup navigation before the Folio shell scrubs it. Exact tested heads and results
belong to the review and landing receipts, not a production claim.


## Installation grant key cutover

Before deploying this build, mount an owner-readable signing-key file for
`folio:grant-read-1` in `FOLIO_APP_KEY_FILES`. Its purpose is `app-grant-read`
only, separate from `folio:emit-1` and its existing emit seed/file. A missing
grant key refuses startup; an emit seed cannot substitute for it.

Folio uses manifest v2. Install by origin so discovery follows the variant
catalog to `/manifests/v2.json`; `/aweb-app.json` serves the same filled bytes.
There is no v1 deployment-manifest fallback. The grant key changes the manifest
digest: deploy the server with installation creation-time grant status first,
then Folio, then explicitly re-pin every existing team installation. A team
whose pin cannot authenticate G1 remains refused until its re-pin. Existing
resident identities and their keys remain unchanged.

The shared TeamGrantSource uses Folio's filled manifest digest and the runtime's
one TeamServerDirectory. No deploy, key provisioning or pin update is performed
by landing this code; those are separately authorized operator actions.
