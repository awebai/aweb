# App registry and team grants

Status: **current experimental public contract**. Owner: the aweb OSS server
extension surface. The implementation lives in `server/src/aweb/app_registry.py`
and `server/src/aweb/routes/apps.py`; the schema is added by
`server/src/aweb/migrations/aweb/008_app_registry_grants.sql` and
`009_app_events.sql`. HTTP behavior is covered by
`server/tests/test_app_registry_http.py`.

This registry is optional and is not part of aweb's default communication
journey. It records app metadata, a digest pin, and per-team granted scopes. It
is not an app marketplace, a source of canonical manifest bytes, or a promise
that a hosted gateway dynamically composes tools.

## Relationship to app manifests

The manifest format and interpretation rules live in
[`app-manifest.md`](app-manifest.md). An app publishes exact bytes at:

```text
<origin>/.well-known/aweb-app.json
```

The registry stores the app id, origin, app version, manifest version, and
`sha256:<lowercase hex>` digest of those exact bytes. It does **not** fetch the
origin or verify that the supplied digest matches the served manifest. The
installer is responsible for fetching, validating, and hashing the bytes before
calling the install route. Consumers must compare cached bytes with the recorded
digest; a registry row is not evidence that this verification occurred.

## Install or update

```http
POST /v1/apps/install
```

Authentication: normal team-certificate auth. The authenticated certificate
selects the team; there is no `team_id` in the request body.

```json
{
  "app_id": "folio",
  "origin": "https://folio.example",
  "app_version": "1.4.0",
  "manifest_version": 1,
  "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
  "granted_scopes": ["folio:read", "folio:write"],
  "events": [
    {
      "type": "doc.changed",
      "default_delivery_intent": "wake",
      "description": "A document changed."
    }
  ],
  "event_emitters": [
    {"kid": "emit-2026-06", "did_key": "did:key:z6Mk..."}
  ]
}
```

The response is the installed-app projection:

```json
{
  "app_id": "folio",
  "origin": "https://folio.example",
  "app_version": "1.4.0",
  "manifest_version": 1,
  "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
  "granted_scopes": ["folio:read", "folio:write"]
}
```

Current rules:

- `app_id` is lower-case, path-safe, and cannot collide with a reserved `aw`
  top-level command id. The shared reserved set is
  `test-vectors/reserved-app-ids-v1.json`.
- One app id has one origin per team, bound by that team's install. Reinstalling
  an app id from another origin in the same team conflicts with `409`. Another
  team's install of the same app id, from any origin, binds only that team.
- An origin is an `http` or `https` origin only: no userinfo, path, query, or
  fragment. Production operators should require HTTPS at their policy boundary;
  the experimental OSS route permits HTTP for local deployments.
- Reinstalling the same team/app/origin explicitly replaces its digest,
  app-version projection, scopes and event declarations, and registers the
  supplied emit keys for the new digest. Publishing new bytes at the origin
  does not silently update an installation.
- Event declarations, emit keys and the app-version projection belong to the
  installing team. Another team's install of the same app and digest never
  changes this team's declared types, default delivery intents or
  descriptions, and a key registered by one team is never active for another
  team. Within
  a team, a key id keeps the `did_key` it was first registered with: an install
  supplying a different `did_key` for a registered key id is refused with
  `409`, and the install is not applied. Rotate a key under a new key id.
  Reinstalling never reactivates a revoked key. Key identity and revocation
  history span both v1 `event_emitters` and v2 `app_keys`: changing manifest
  version never resets either. Registration carries the earliest revocation
  for the same team, app, key id and `did_key`; verification also checks that
  shared history, including rows registered before the version switch.
- Scopes are normalized and stored. Without `manifest` (below), the server
  cannot prove that the granted scopes are within the manifest's
  `tools[].scopes`.
- Event declarations are app-local names. Emit keys are public `did:key`
  material; private emit keys never belong in a manifest or install request.
- No public uninstall route ships today. Do not document uninstall or automatic
  upgrade as current behavior.
- Each install or update, accepted or refused after authentication, writes one
  append-only operator audit row (`apps.install`, target `app:<app_id>`); a
  successful install's row commits with its registrations
  ([operator audit](operator-audit.md)).

### Installing with the manifest bytes

The request may carry `manifest`: standard base64 of the exact bytes the app
serves, at most 10 MiB. The install body is read under a bound of that encoded
size plus 1 MiB, and refused with `413` before it is parsed when it is larger;
a `manifest` over the encoded bound is also `413`. `aw plugin install` and
`aw plugin update` send the bytes for `manifest_version` 1 manifests, unless
`--dev-origin` registers the app at an origin its bytes do not declare. When
present:

- the bytes must hash to `digest` and name the request's `app_id`, `origin`,
  `app_version` and `manifest_version`;
- the bytes must be a valid manifest of either version, read by the one
  manifest reader that apps and clients share (`aweb_naapp.manifest`, held to
  `test-vectors/app-manifests/app-manifest-v2-v1.json`). A manifest it refuses
  is refused with `422`, and the detail carries its stable code;
- `events` come from the bytes; version 1 `event_emitters` are the app's
  app-event keys. If the request also supplies them, they must equal the
  bytes' declarations;
- version 2 `app_keys` register the app's keys with the purposes the bytes
  declare for each. They come only from the bytes; there is no request field.
  A key id keeps its first `did_key` in the team, so a later install naming a
  different key for it is refused with `409` and nothing is written, and a
  revoked key stays revoked. A purpose label the server does not know is
  stored and grants nothing. A key that declares `app-event` signs app events;
- `granted_scopes` must be a subset of the scopes the bytes' tools request; a
  team may grant less, never more.

A disagreement refuses the whole install with `422`, and nothing is written.
An install without `manifest` behaves as before and registers the supplied
fields. Each install row records which way it was registered, so an operator
can measure when every client sends the bytes before requiring them:

```sql
SELECT registered_from_manifest_bytes, count(*)
FROM aweb.team_app_installs
GROUP BY registered_from_manifest_bytes;
```

## Read installed apps and grants

```http
GET /v1/apps/installed?team_id=<name:domain>
```

Authentication: team-certificate auth for the requested team. The source also
supports a trusted host-integration read context, but that internal header
scheme is not a portable third-party protocol; independent clients use team
auth.

Response:

```json
{
  "team_id": "default:example.com",
  "apps": [
    {
      "app_id": "folio",
      "origin": "https://folio.example",
      "app_version": "1.4.0",
      "manifest_version": 1,
      "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
      "granted_scopes": ["folio:read", "folio:write"]
    }
  ]
}
```

- Apps are ordered by `app_id`.
- A team with no installs receives `200` with `apps: []`.
- V1 has no pagination.
- `400` means invalid `team_id`; `401`/`403` means the caller cannot read that
  team; storage failures are server errors.

## Hook bindings

An installed app's declared hook registrations and productions are its hook
bindings (`docs/design/audit-substrate.md` §A3; the catalog is
`docs/hook-events.md`). Each install generation writes its bindings as
`pending`. Only the team owner moves one to `active` or `revoked`, with an
`aweb.owner-act/1` (`docs/owner-act.md`) whose subject names exactly the stored
binding. A new generation supersedes every earlier binding (`superseded`), so an
activation is never inherited, and uninstall revokes the live ones.

```http
GET /v1/apps/hook-bindings?team_id=<name:domain>&app_id=<app_id>
```

Authentication: team-certificate auth for the requested team, as for the
installed-apps read. Every binding of the app in the team is returned, in every
state:

```json
{
  "team_id": "default:example.com",
  "bindings": [
    {
      "binding_id": "6f1c4d2e-0b7a-4c55-9a51-2f6d0e8b1a90",
      "kind": "registration",
      "team_id": "default:example.com",
      "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
      "generation": 1,
      "app_id": "logs",
      "origin": "https://logs.example",
      "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
      "catalog_id": "aweb.hooks",
      "catalog_version": 1,
      "hook": "post-secret-use-hook",
      "tool": "ingest",
      "method": "POST",
      "path": "/hooks/ingest",
      "scopes": ["logs:append", "logs:write"],
      "reads": [],
      "state": "active",
      "ended_by": null,
      "activated_at": "2026-10-20T12:00:00.000Z",
      "active_from": "2026-10-20T12:01:00.000Z",
      "revoked_at": null
    }
  ]
}
```

- A registration names its resolved `tool`, `method`, raw `path` and `scopes`;
  a production has those null or empty and names its `reads`. Both lists are
  sorted by code point and distinct, the order the owner act's subject uses.
- Times are stored and returned to the millisecond. `active_from` is exactly
  60 s after `activated_at`, so every producer has refreshed before the binding
  receives an event, and no history is delivered to it.
- `ended_by` is `owner_act`, `uninstall` or `generation` once a binding ends.

```http
POST /v1/apps/hook-bindings/{binding_id}/activate
POST /v1/apps/hook-bindings/{binding_id}/revoke
```

Body: `{"act": "<standard base64 of the signed bytes>", "signature": "<standard
base64, no padding>"}`, with no other field. The signed bytes are
`aweb.owner-act/1\n` followed by the act's canonical JSON. Authentication:
team-certificate auth; the caller's team scopes which bindings the request can
name, and the owner act is the authority for the change.

- The act's `act` is `hook-binding.activate` or `hook-binding.revoke` for the
  matching route, its `aud` is the server's public origin, and its signature
  verifies against the team's controller key read fresh from AWID. It is
  single-use.
- Its subject is the binding as listed, with `catalog_id` and `catalog_version`
  flat. A registration's subject carries `tool`, `method`, `path` and `scopes`;
  a production's carries `reads`.
- Activation needs a `pending` binding whose install carries its installation
  identity. A production activates only when its install registered, from its
  pinned manifest bytes, a key declaring `hook-event`, the purpose consumers
  verify its events with.
  Revocation takes a `pending` or `active` binding.
- The answer is the changed binding. Refusals:
  - `404`: the binding is not the caller's team's.
  - `403`, with the owner-act refusal code (`docs/owner-act.md`): any refusal
    of the act itself, from malformed or non-canonical bytes to `owner_required`,
    `team_mismatch`, `audience_mismatch`, `expired` or `act_not_allowed`.
  - `409`: `subject_mismatch` or `nonce_reused`, or a binding that is
    superseded, ended, not pending, without installation identity, or a
    production without a `hook-event` key.
  - `422`: a malformed request body, including an `act` that is not standard
    base64.
  - `503`: AWID cannot be reached for the team's key. Nothing is changed, and
    the same act can be retried.

## An app reads its own grant

```http
GET /v1/apps/self/grant
Authorization: AWEB-App-Grant-Read DIDKey <did:key> <signature>
```

The app signs the request with one of its own keys under the `app-grant-read`
purpose. The headers and the signed payload are those of the app-event
credential ([App events](app-events.md)), with `auth` set to
`app-grant-read`, `method` `GET` and `body_sha256` the SHA-256 of the empty
body. The signature is unpadded standard base64 in its one canonical
encoding: 86 characters, the last one `A`, `Q`, `g` or `w`. A padded,
URL-safe or otherwise re-encoded signature is refused.

The key must be registered for `app-grant-read` under the team's installed
digest. Such keys come only from the `app_keys` of the pinned manifest bytes;
an `event_emitters` key never signs this request.

Response:

```json
{
  "team_id": "default:example.com",
  "app_id": "folio",
  "state": "active",
  "origin": "https://folio.example",
  "app_version": "1.4.0",
  "manifest_version": 2,
  "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
  "granted_scopes": ["folio:read", "folio:write"],
  "installation_id": null,
  "generation": null,
  "origin_verified": null,
  "as_of": "2026-10-20T12:00:00Z",
  "max_age_seconds": 60
}
```

- The team and the app come from the verified credential, never from the
  query, so an app reads only its own grant in the team that signed for.
- `state` is `active`. Any other state grants no normal use.
- `installation_id`, `generation` and `origin_verified` are always present and
  `null` until installations carry them. A consumer that binds them refuses
  `null`. `origin_verified` says whether the server verified the pinned bytes
  against the app's origin; bytes being present is not that.
- `as_of` is the server's time of the answer, in UTC seconds.
- `max_age_seconds` is how long the app may reuse the answer, counted from
  when it asked for it. It is `AWEB_APP_GRANT_MAX_AGE_SECONDS`, from 1 to 60
  seconds, default 60; the server refuses to start with any other value.
- A reinstall with new bytes is visible on the next read: keys belong to their
  digest, so the old digest's keys are refused and the new digest's keys read
  the new grant.
- `401` means a malformed, mismatched or unsigned credential, including one
  signed for another purpose. `403` with detail `app_key_not_registered` means
  no key is active for `app-grant-read` under the team's installed digest,
  which is also the answer once the app has no installation.

Conformance: `test-vectors/app-read-credential-v1.json`.

### App-side grant source

`aweb_naapp.runtime.team_grants.TeamGrantSource` consumes the runtime's shared
`TeamServerDirectory`, an `app-grant-read` signer, and the app's own
`AppIdentity` (app id, public origin and served-manifest digest). Every answer
must name that exact identity and the requested team. A changed server record
selects a separate cache entry, so an old server's answer cannot follow a move.
The app signs the full external request path, including any server mount prefix,
and follows no redirects.

`grant_for(team_id)` returns B1's active `Grant` or `None` for a non-active
installation or `403 app_key_not_registered`. `status_for(team_id)` uses the
same read and cache to return `GrantStatus`, preserving non-active and unknown
states and nullable installation identity, generation and origin provenance.
`None` means the calling key has no grant; it does not prove an uninstall.
Only a typed `uninstalled` status confirms that state to the installation fence.
The explicit missing-key denial is cached for at most five seconds, so an app
called before installation can become usable promptly after installation.

The freshness deadline uses the client's monotonic clock, counting from the
start of the shared read, with a ceiling of 60 seconds. A slow answer earns no
extra time, and an answer already expired when received is unavailable.
Concurrent misses share one refresh; a cancelled waiter does not cancel that
refresh for other callers. The default total caller timeout is 5 seconds,
including discovery. Discovery failures, refused credentials other than the
explicit missing-key result, failed reads and malformed or mismatched answers
raise `GrantUnavailable`. Expired positive answers never survive a failed refresh.

## An app resolves its hooks

```http
GET /v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/registrations
GET /v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/productions
GET /v1/apps/self/hooks/bindings?binding_id=<uuid>
GET /v1/apps/self/hooks/bindings?hook=<catalog_id>/<catalog_version>/<hook>
Authorization: AWEB-App-Hook-Resolve DIDKey <did:key> <signature>
```

The app signs each read under the `hook-resolve` purpose, exactly as for the
grant read (same headers, signed payload and one-encoding signature), with
`auth` set to `hook-resolve`. The signed `path` is the request target with its
query. The key must be registered for `hook-resolve` under the team's installed
digest. The team and the app come from the credential.

A binding is **active** by its state: activated by the team owner, not revoked,
and of the installation's current generation. That includes a binding still
inside its pad before `active_from`: the reader compares `active_from` with an
event's `occurred_at`. Pending, revoked and superseded bindings are never
listed and never authorize.

- **Registrations** answer a producer: where to deliver. They are read only
  while the caller holds an active production of that exact hook.
- **Productions** answer a target: who may produce the hook, and with which
  keys. They are read only while the caller holds an active registration of
  it. Each production also carries `keys`: the producer's unrevoked keys, registered under
  its own installed digest, that declare `hook-event` or `hook-delivery`, as
  `{kid, did_key, purposes}`. A key with neither purpose is never listed.
- Without the complementary binding the answer is `403 hook_binding_required`.
  An unknown catalog, version or hook therefore also answers `403`.
- A member's team-auth envelope is refused with `401`, like any credential
  that is not `hook-resolve`.

```json
{
  "team_id": "backend:acme.com",
  "catalog": {"id": "aweb.hooks", "version": 1},
  "hook": "post-secret-use-hook",
  "bindings": [
    {
      "binding_id": "6f9619ff-8b86-4011-b42d-00c04fc964ff",
      "kind": "registration",
      "app_id": "logs",
      "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
      "generation": 2,
      "origin": "https://logs.example",
      "method": "POST",
      "path": "/hooks/ingest",
      "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
      "active_from": "2026-10-20T12:01:00.124Z"
    }
  ],
  "as_of": "2026-10-20T12:00:00Z",
  "max_age_seconds": 60
}
```

**Own bindings** return the caller's own bindings in the team from its
installed origin, in every state and across that origin's digests, so a
superseded generation's bindings are included. Bindings an earlier origin left
under the same app id are another publisher's and are never shown. They are
selected by exactly one of `binding_id` or `hook`, each with its `catalog`,
`hook`, `state` (`pending`, `active`, `revoked` or `superseded`), `ended_by`
(`owner_act`, `uninstall` or `generation`) and `activated_at`, `active_from`
and `revoked_at`, null when they do not apply. A target confirms a delivery's
`binding_id` this way, and records each binding's interval. Another app's
binding id reads as no binding. A missing, doubled or malformed selector is
`400`.

Binding times are UTC to the millisecond (`YYYY-MM-DDTHH:MM:SS.mmmZ`), the hook
event spelling; `active_from` is rounded up, so a binding never reads as active
earlier than it is. `as_of` and `max_age_seconds` are as for the grant read.

Conformance: the `hook-resolve` cases of `test-vectors/app-read-credential-v1.json`.

## The core hook producer's keys

```http
GET /v1/hooks/producer-keys
```

Anyone may read the public keys this server's core hook producer signs
`post-mutation-hook` events with. A consumer reaches the server only through
the team's anchored `aweb.team-server/1` record, never through an origin an
event names.

```json
{
  "keys": [
    {"kid": "hook-2026-09", "did_key": "did:key:z6Mk...", "valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-10-01T00:00:00Z"},
    {"kid": "hook-2026-10", "did_key": "did:key:z6Mk...", "valid_from": "2026-10-01T00:00:00Z", "valid_until": null}
  ],
  "as_of": "2026-10-20T12:00:00Z",
  "max_age_seconds": 60
}
```

- The keys are the operator's configuration, `AWEB_HOOK_PRODUCER_KEYS`: a JSON
  list of `{kid, did_key, valid_from, valid_until}`, times in UTC seconds
  (`YYYY-MM-DDTHH:MM:SSZ`, ASCII digits). They are never a team, controller or
  agent key.
- Retired keys stay listed, so events they signed keep verifying.
  `valid_until` is `null` for a key with no end; it is never omitted, so a
  missing end cannot be mistaken for a truncated answer.
- The server refuses to start with a malformed list: an entry with other
  fields, a repeated kid, an invalid Ed25519 `did:key`, a time in another
  spelling or an impossible date, or a key that ends before it starts.
- `as_of` and `max_age_seconds` are as for the grant read.

## Operator reseed from manifest bytes

```sh
aweb reseed-app-registrations --origin https://notes.example
aweb reseed-app-registrations --origin https://notes.example --manifest-file notes-1.2.0.json
```

An operator command, run against the server's database. It takes the exact
manifest bytes the origin serves at `/.well-known/aweb-app.json` (over
https, or plain http to a loopback host only; a direct `200`, no redirects, at
most 10 MiB), or a file of exact bytes. For every team
whose install of that app and origin pins the SHA-256 of those bytes, it
recreates the team's event declarations, emit keys and version projection
from the bytes alone. The bytes must name the installed app id and origin.

- Subscriptions are never changed.
- Teams pinned to another digest are reported as `digest_mismatch` and left
  unchanged; reseed them with their own pinned bytes through
  `--manifest-file`.
- A team whose key id already holds a different `did_key` is reported as
  `key_conflict` and left unchanged.
- Running it again changes nothing further. It exits `1` when any team was
  left unchanged, and prints the report as JSON.

Upgrading a server to team-scoped registrations: the migrations do not carry
registry-entry keys or declarations over, because those rows record no
installing team. App events for existing installs are refused until either
the operator reseeds each installed app or the team installs the app again.
Run the migrations, then reseed every installed app origin.

## Cache and consumer boundary

The registry is authoritative for its own stored tuple
`(team_id, app_id, origin, digest, granted_scopes)`. Canonical manifest bytes
remain at the app origin and in each consumer's digest-verified cache.

A consumer may cache the installed-app read through transient failures, but it
must keep the digest and origin together and must never reinterpret different
bytes under the old digest. Connector grants, human accounts, billing, and a
hosted operator's tool-composition policy are outside this OSS contract.

## Lifecycle limits

This surface is experimental: route and schema changes require corresponding
source tests and documentation review. The digest pin and explicit-update rule
are compatibility constraints. App installation is not required for mail, chat,
events from built-in coordination mutations, or self-hosting the core
communication service.

## App-side installation admission and dispatch fence (X9)

`aweb_naapp.runtime.installation` supplies the shared PostgreSQL fence. Apply
`apply_installation_migrations(db)` during startup, then construct one
`InstallationFence(db, app_id=app_id, grants=team_grant_source)` per app. The
source supplies B1's `grant_for` and the additive `status_for` method through
the same authenticated read and bounded cache. The remote implementation and
concrete `GrantStatus` type belong to the generic app-to-team-server API.

Admission obtains B1's authenticated, fresh `Grant`, then creates
`admission_fence = fence.for_admission(grant)` and passes it to
`dispatches.admit(tx, dispatch_id, fence=admission_fence)`. Store
`admission_fence.admitted`'s `team_id`, `app_id`, `installation_id` and
`generation` with the intent after admission succeeds. S3 calls the bound
fence's `prepare(tx)` before its pair advisory lock and intent-row lock;
preparation records the installation under its update lock. It then calls
`check(tx, dispatch)` under its locks, without taking a new fence-row lock.
The observation rolls back with admission. Missing identity is refused, never
synthesized. Committed observations cannot lower a generation or revive a
retired ID. Only a typed confirmed `uninstalled` status or a typed active
replacement at a strictly higher generation permanently retires an installation. Pending verification and
unknown non-active states disable shared use without retirement; a fresh active
status may restore the same ID and generation, never a lower generation.

The server allocates generation from a persistent per-`(team, app)` counter:
it strictly increases across installation IDs, including reinstallations, and
is never reused. Uninstall never deletes that counter. The fence compares this
generation before changing shared state. A lower generation refuses the caller
without writes. An equal generation with a different ID is an authority
inconsistency and gets `authority_unavailable`, also without writes. A higher
generation with the same ID is an update. A higher generation with a different
ID is a replacement only when active. Pending/unknown observations advance
the highest observed generation and disable shared use, but retain the last
active identity separately; its authority is retired only when the replacement
becomes active or an ordered confirmed uninstall is observed.

`status_for` returning `None` means the calling replica's configured key/digest
is denied. That caller gets `installation_inactive` (403), with no shared-state
write or retirement hook. Repeated refreshes from an old replica therefore
cannot disable the healthy replica's current generation. Uninstall is reported
as a typed status, never inferred from `None`.

Before dispatch, refresh outside the dispatch transaction and its intent lock:

```python
await fence.refresh(team_id)
async with db.transaction() as tx:
    await dispatches.begin_dispatch(
        tx, dispatch_id,
        fence=fence.for_installation(admitted),
    )
```

`refresh` uses ordinary `status_for` cache semantics, never a forced refresh. It
commits an active/inactive observation in its own short transaction. Failed
refresh invalidates local freshness and stops dispatch. Refresh before resumed
dispatch even when there have been no new admissions: an idle app must learn
uninstall. S3 enforces the same two-phase order on `begin_dispatch` as on
`admit`: `prepare` takes the shared fence lock before any pair/intent locks,
then `check` validates active state, ID/generation and freshness under those
locks. Both phases perform SQL only. The shared fence lock lasts through the
dispatch commit, serializing it with local authority observations. The global
order is **fence, dispatch row, pair**, enforced inside S3 rather than by a separate
call the app must remember. Each operation gets a new bound fence object.

Without S3, `fence.admit(tx, grant)` and `fence.check(tx, admitted)` remain
standalone transaction-level operations; call them before app resource locks.
The shared lock is acquired in one query and freshness evaluated by a second
query after waiting. A clock projection in the locking query can be evaluated
before the wait and must not authorize a dispatch after expiry.

An expired observation refuses even when refresh is not running. PostgreSQL
stores the source's remaining monotonic freshness; waiting for the fence lock
does not renew it, and a process restart does not reset it. Admission samples
the SQL clock after acquiring its lock, then the remaining monotonic lifetime;
a pre-wait clock would wrongly subtract the lock wait twice. Across the remote
team server and app the guarantee is **max_age plus one bounded refresh**, at
most **60 + 5 seconds with the remote source's defaults**. The source's freshness
window begins at the start of the shared refresh that fetched the answer;
every single-flight waiter gets
that same deadline. Receipt or a later waiter never renews it. The fence
preserves the supplied deadline's remaining lifetime rather than starting a
new window.

A local lock is not a cross-server lease. Earlier committed work is reconciled,
never reported as rolled back. Immediate app-local containment is a separate
authority operation.
Before an uninstall is observed, a stale higher generation can be honoured for
at most one cache window (60 + 5 s) after the remote uninstall. Once a confirmed
typed uninstall is recorded, no cached active grant can revive that ID.

Apps that hold installation authority pass an asynchronous
`on_retire(tx, team_id)` hook to `InstallationFence`. For role assignments,
pass `aweb_naapp.roles.purge_team`, composed with any other authority cleanup.
The hook runs inside the transaction that records a confirmed uninstall or
retires an old ID before admitting a replacement. It also covers an app that
was down during uninstall and first observes the replacement on admission.
Hook failure rolls back retirement and new admission together. The withdrawal
lock order in the caller's transaction is **installation fence, role DELETE or
`purge_team`, `approver_retired` with approval IDs locked in order, then writes**.
Compose the hook in that order: remove roles before retiring approvals.
Staging takes the installation fence, `hold_role`, then approval and candidate
locks before writes. Retiring approvals before removing roles creates a lock
cycle with a concurrent stage. The same fence-before-role order applies to
unassign, team purge and owner revoke whenever they also require the fence.
App content follows its retention policy; authority cleanup is separate from
content deletion.

`InstallationRefused` carries `code` and HTTP-compatible `status`:

| Code | Status | Meaning |
| --- | --- | --- |
| `installation_identity_required` | 403 | Authority omitted a nonempty ID or positive generation. |
| `installation_inactive` | 403 | Installation is not granted, or the ID was retired. |
| `generation_superseded` | 409 | A different installation or generation superseded the admission. |
| `authority_unavailable` | 503 | Authority is unreachable, mismatched or no longer fresh. |

Consumers own outward error/audit mapping and must stop when refresh or check
refuses. The store holds opaque installation references and freshness, never
app content or credential material. X9 consumes the team server registry's
authority.
