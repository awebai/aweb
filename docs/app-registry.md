# App registry and team grants

Status: **current experimental public contract**. Owner: the aweb OSS server
extension surface. Implementation: `server/src/aweb/app_registry.py` and
`server/src/aweb/routes/apps.py`.

The registry records each team's installation identity, pinned manifest bytes,
origin, generation, scopes and state. It is optional: core mail, chat and
coordination do not require an app installation.

## Install, update and management reads

See [Installation management HTTP API](app-installation-api.md) for preview,
confirmation, member requests, admin approvals and re-verification. The server
fetches exact bytes from the declared HTTPS origin through shared egress and
interprets them through `aweb_naapp.manifest`. A failed origin fetch refuses the
installation. Installer-uploaded bytes and separately supplied keys, versions
or event declarations are not installation authority.

Mutations require the host's current install-admin policy on every ingress,
including a mounted server and the CLI. Updates require the previous generation;
an update never silently replaces a concurrent change. Granted scopes are a
subset of the shared reader's agent/surface install scopes. Hook-only scopes
await separate owner activation. Every generation leaves declared hooks pending.

`GET /v1/apps/installed?team_id=...` exposes active, origin-verified installations
only, ordered by app ID. Management reads under `/v1/apps/installations` and
`/v1/apps/{app_id}/installation` also expose pending and uninstalled records,
which confer no ordinary authority. Authentication is verified team auth or the
host's verified internal context; the requested team must match it.

A key ID keeps its first `did_key` within a team and app. A conflicting key is
refused with 409 and nothing is written. Identity and revocation history span both v1 emitters and v2 app keys.
Revocation survives digest and manifest-version changes; reinstall never
reactivates a revoked key. Purpose labels come from pinned
bytes. An unknown purpose is stored and grants nothing. Private keys never
belong in manifests or installation requests.

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
  "installation_id": "opaque-installation-id",
  "generation": 1,
  "origin_verified": true,
  "as_of": "2026-10-20T12:00:00Z",
  "max_age_seconds": 60
}
```

- The team and the app come from the verified credential, never from the
  query, so an app reads only its own grant in the team that signed for.
- `state` is the current registry state, including `pending_origin_verification`
  and `uninstalled`. Only `active` grants normal use. The grant-read key remains
  usable for these non-active status reads; ordinary key purposes do not.
- `installation_id`, `generation` and `origin_verified` come from the shared
  installation reader. A consumer that binds identity refuses missing values.
  `origin_verified` records the server's verification of the exact pinned bytes.
- `as_of` is the server's time of the answer, in UTC seconds.
- `max_age_seconds` is how long the app may reuse the answer, counted from
  when it asked for it: the start of the shared refresh. It is `AWEB_APP_GRANT_MAX_AGE_SECONDS`, from 1 to 60
  seconds, default 60; the server refuses to start with any other value.
- A reinstall with new bytes is visible on the next read: keys belong to their
  digest, so the old digest's keys are refused and the new digest's keys read
  the new grant.
- `401` means a malformed, mismatched or unsigned credential, including one
  signed for another purpose. `403` with detail `app_key_not_registered` means
  no key is active for `app-grant-read` under the team's installed digest,
  which is also the answer once the app has no installation.

Conformance: `test-vectors/app-read-credential-v1.json`.

## Operator reseed from manifest bytes

```sh
aweb reseed-app-registrations --origin https://notes.example
aweb reseed-app-registrations --origin https://notes.example --manifest-file notes-1.2.0.json
```

This operator repair command derives registrations from exact bytes whose hash
matches the stored pin. A supplied file can repair declarations; it is never
origin verification and cannot activate a pending installation. Without a file,
the command uses the shared HTTPS origin fetcher, catalog discovery and bounds.
Revoked keys stay revoked, conflicting key IDs refuse, subscriptions stay as
selected, and other digests are left unchanged.

After the F6 migration, run `aweb verify-pending-app-installations` immediately.
Existing app authority pauses until each pinned origin is verified. The command
preserves scopes, identity, generation and pin; a failure leaves the row pending
with an admin-visible reason. Core mail and chat remain available. For queued
admin retries, run `aweb run-installation-verifications` periodically on a worker.
Neither migration nor the re-verify HTTP request fetches an old installation.

## Cache and consumer boundary

The registry is authoritative for its own stored tuple
`(team_id, app_id, origin, digest, granted_scopes)`. The exact verified bytes are retained with the installation and remain
available from the app origin and each consumer's digest-verified cache.

Consumers keep digest and origin together and never reinterpret different
bytes under the old digest. App authority uses the bounded, fail-closed grant
source and the installation fence below; an expired grant is never reused
through an outage. Connector grants, human accounts, billing, and a
hosted operator's tool-composition policy are outside this OSS contract.

## Lifecycle limits

This surface is experimental: route and schema changes require corresponding
source tests and documentation review. The digest pin and explicit-update rule
are compatibility constraints. App installation is not required for mail, chat,
events from built-in coordination mutations, or self-hosting the core
communication service.

## Host installation policy interface

`aweb.install_authority.require_install_admin(tx, request, identity, team_id,
*, action, app_id)` is the shared administration check for installation
mutations and team app-key revocation. Certificate ingress passes its verified
`TeamIdentity`; authenticated internal ingress may pass `None`. Internal context
is verified through the existing proxy trust/HMAC verifier.

The serving application's `app.state.install_admin_policy` implements
`InstallAdminPolicy`: `async __call__(tx, subject, *, action, app_id) -> bool`.
It reads current authority inside the passed mutation transaction. A standalone
operator configures authority rooted in its team controller and explicit
delegations; an embedding host supplies its authoritative policy. A configured
host policy is the only source: its denial never falls back to standalone grants.
Without a host policy, the standalone policy reads an operator-managed grant
for the verified member's `did:key` inside the mutation transaction, holding
`FOR SHARE` until commit. No grant, or a result other than `True`, produces
`403` with code `admin_required`.
Membership, custody, audit attribution and role strings confer no installation
administration authority. Identity session grants cannot acquire it through
their coordination scopes.

The immutable `InstallAdminSubject` union has two verified variants:

| `kind` | Verified fields |
| --- | --- |
| `certificate` | `team_id`, `agent_id`, `certificate_id`, `did_key` |
| `internal` | `team_id`, `principal_type`, `principal_id`, `actor_id` |

Internal principal type remains distinct from the attributed actor; the host
decides which authenticated principal kinds may administer. Policy exceptions
fail the mutation. Decisions are not cached. Install the policy on the actual
serving/mounted application so certificate and internal ingress use the same
check. Installation confirmation, request approval and queued re-verification
use it on both certificate and internal ingress; uninstall uses it in the
lifecycle service. Ordinary members can submit installation requests without
granting authority. See [the installation API](app-installation-api.md).

## Standalone installation administrators

The server starts with no install-admin grants and prints bootstrap guidance;
core mail and chat keep working. A server operator grants the first owner
locally, using the normal server database configuration:

```sh
aweb install-admin grant --team-id TEAM --principal-did did:key:MEMBER --role owner
aweb install-admin list --team-id TEAM
aweb install-admin grant --team-id TEAM --principal-did did:key:ANOTHER --role admin
aweb install-admin revoke --team-id TEAM --principal-did did:key:ANOTHER
```

These are local server commands, not `aw` member commands. There is no HTTP
grant/revoke route. `team_app_install_admins` records team, principal DID,
owner/admin role, database operator, grant time and revocation time. Changes
and their content-free operator audit commit together. Revoking or demoting
the last owner requires an explicit `--force`. A revoked grant stops authorizing
new mutation transactions; an already-authorized transaction holds its grant
until commit. Certificate membership and member-writable agent/workspace role
labels or prompt-role bundles do not confer this authority. Internal-auth
hosts must provide their own policy; no internal actor is guessed into a DID.

Grants are keyed by the member's `did:key`. After a member rotates keys, the
new key has no install-admin authority until the server operator re-grants it
with `aweb install-admin grant`. Key rotation does not transfer the old grant;
the operator should also revoke the grant for the old key.

## Installation identity and transactional reader

Migration `033_team_app_installation_identity` adds an opaque, unique
`installation_id`, a positive `BIGINT` generation, install state, per-install
`origin_verified`, a bounded verification error code and exact pinned manifest
bytes. State is `pending_origin_verification`, `active` or `uninstalled`.
Active rows require origin verification and bytes matching their pinned SHA-256
digest. Existing rows receive new IDs and generation 1 without changing their
origin, digest or granted scopes.

Existing rows begin in `pending_origin_verification`: installer-supplied bytes
were not proof that this server fetched the origin. Migrations perform no
network access. A separate operator/admin verification job must fetch the
original pinned bytes before activating a pending row, preserving its ID,
generation and scopes. Until then normal app authority fails closed; core mail
and chat are unaffected. Deploy plans must run the pending-row verifier
immediately after migration to keep the app interruption short. The schema and
reader ship with origin-fetch enforcement and state guards on existing registry
lookups; a schema-only cutover is not supported.

`aweb.app_registry.get_installation_on(tx, *, team_id, app_id,
for_update=False)` returns the current row or `None`. Its projection includes
`installation_id`, `generation`, `state`, `origin`, `digest`, `granted_scopes`,
`origin_verified`, version metadata and `origin_verification_error`. It does not
load manifest bytes for ordinary authority reads.

Task ingress, authorized receipt reads and lifecycle mutations pass
`for_update=True`. They lock the same current installation row with
`FOR UPDATE OF i` inside their own transaction. Retirement therefore serializes
with task admission; both services use this reader. Generations change on
updates or scope changes; reinstall uses a new ID. Neither an absent row nor
a non-active state confers normal app authority.


Generation is strictly increasing per `(team_id, app_id)`, across installation
IDs. A new installation ID continues the order rather than resetting it.
`next_installation_generation_on(tx, team_id=..., app_id=...)` allocates the next
value in the same registry transaction. Existing-installation writers hold the
installation row lock and validate the caller's expected generation first.
`team_app_install_counters` survives uninstall and removal of the installation
row, and also survives deletion and recreation of the team itself. Counter
rows are never deleted, so reusing a team ID cannot reset app authority. Every install,
update and scope change uses the allocator. A rolled-back transaction issues
no generation. Migrated current installations and their counters start at 1.

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
