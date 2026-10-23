# Installation management HTTP API (F6 draft)

This is the implementation contract being built for F6. These routes are not
all implemented or available on main yet. The registry schema, ordinary-use
guards and origin-fetch cutover land together. The app-facing grant API is
separate; see [app-registry.md](app-registry.md).

All paths below are relative to the OSS server mount. Authentication is the
existing verified team-auth or internal-auth context. `team_id` may identify the selected team in the query and must match that
context; omitting it uses the authenticated team. Body
fields never establish the caller's identity, team or installation authority.

The host installs `app.state.install_admin_policy` on the serving application.
Install, update, uninstall, request approval and re-verification check current
host policy inside the mutation transaction. The standalone policy requires
an operator-managed admin grant. The named refusal is
`403` with `detail.code: "admin_required"`; another team's context gets `404`.
Ordinary members can preview and request an installation, without granting use.

Install/update and request approval first check the optional
`app.state.install_admission_policy(tx, subject, *, action, app_id,
unverified_origin)`. This admits only fetching; the requested origin is an
unverified hint. If absent, admission uses the existing admin policy.
Final authorization always calls `install_admin_policy(tx, subject, *, action,
app_id, verified_origin=fetched.origin)` inside the writing transaction, after
the server verifies the fetched manifest. A preliminary allowance cannot
authorize the write. Final refusal leaves the installation and success audit
unchanged. Other actions retain their existing policy calls. See the
[host policy contract](app-registry.md#host-installation-policy-interface).

Before final authorization, install/update and request approval acquire the
writer's transaction-scoped installation lock, then the current row lock. The
installation lock also serializes first installs when no row exists. Host
policies can read the current installation through their supplied transaction;
they do not need to construct a lock key. The writer reuses the same locks, held
until that transaction commits or rolls back. Admission and network fetching
hold no installation lock.

For actions other than install/update and request approval, host policies must
not lock installation rows; those calls run without the installation lock.

## Preview and confirmation

`POST /v1/apps/preview?team_id=...` accepts:

```json
{"origin":"https://app.example"}
```

The server fetches the catalog and selected manifest through the shared egress
guard, hashes the exact bytes, and interprets them through the shared manifest
reader. It accepts only HTTPS, refuses private destinations and redirects, and
bounds the catalog to 64 KiB and a manifest to 10 MiB. Only a missing catalog
allows the legacy well-known manifest. An unsuccessful fetch grants nothing.

The preview returns:

- `app_id`, `origin`, `digest`, `origin_verified: true`;
- `manifest`: the parsed document, including the declared tools and data policy;
- `resolved`: the shared reader's view, including effective tool contexts,
  install scopes, surfaces, purpose-split keys, hooks, lifecycle and roles;
- `current`: the team's current installation record, or `null`;
- `diff`: added/removed requested scopes and changed tools/endpoints, surfaces
  and app keys/purposes, compared by their identifiers rather than array order.

The digest is the confirmation pin. A client displays that preview and supplies
its digest on confirmation; it does not upload manifest bytes or supply keys,
event declarations or tool mappings separately.

`POST /v1/apps/install?team_id=...` accepts:

```json
{
  "app_id":"fixture",
  "origin":"https://app.example",
  "digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "granted_scopes":["fixture:read"],
  "expected_generation":null
}
```

The server fetches the origin again. Changed bytes return
`409 manifest_changed`, leaving the installation unchanged. The app identity
must match the fetched bytes; granted scopes must be a subset of the shared
reader's `install_scopes`. Hook-only tool scopes are not ordinary install
scopes. Unknown body fields, including separately supplied keys, are refused.

A first installation has no expected generation. An update or reinstall must
supply the current positive generation; omission is `422 generation_required`,
and a stale generation is `409 generation_conflict`. Updates keep the
installation ID. Reinstall after uninstall creates a new ID. Both allocate the
next generation from the persistent per-team/app counter inside the registry
transaction; failed transactions issue no generation.

For the CLI, a new `aw plugin install <origin>` grants the requested install scopes
unless `--grant-scope` selects a smaller set. `aw plugin update <app>` preserves
the team's existing selection by default, dropping scopes the new bytes no
longer request. It never silently grants new scopes; an admin selects those
explicitly with `--grant-scope` (repeat or comma-separate; an empty value grants
none).

Every successful confirmation returns the installation record. It stores the
fetched bytes and their digest, sets `state: "active"` and
`origin_verified: true`, and derives registrations from those bytes. New hook
registrations and productions remain pending their owner's separate activation.
When the team already has an active, origin-verified installation on that same
pin and no `--grant-scope` is supplied, `aw plugin install` joins it locally and
saves the receipt without an install POST. An ordinary member can join the
team's existing installation. An admin repeating install keeps narrowed scopes,
the generation and owner-activated hooks. When confirming different bytes
without an explicit scope selection, install preserves the existing grants
that the new manifest still requests, just as update does.

There is no legacy any-member or unverified-install path.

## Installation reads

`GET /v1/apps/installations?team_id=...` returns
`{"team_id":"...","installations":[...]}` including pending and uninstalled
records. `GET /v1/apps/{app_id}/installation?team_id=...` returns one record or
`404`. These are management reads; the existing `/v1/apps/installed` list
exposes only installations that currently grant ordinary use.

An installation record contains `app_id`, `installation_id`, `generation`,
`state`, `origin`, `digest`, `app_version`, `manifest_version`,
`granted_scopes`, `origin_verified` and `origin_verification_error`.
States are `active`, `pending_origin_verification` and `uninstalled`.
Pending or uninstalled records confer no ordinary authority. Management views
also expose the pinned declarations and the hook owner's authorization states;
install authority never activates an owner-controlled hook.

## Pending verification

Existing rows migrate to `pending_origin_verification`, preserving pins,
scopes and assigned installation identity. Migrations perform no network work.
The deploy operator runs `aweb verify-pending-app-installations` immediately
after migration; ordinary app calls are interrupted until verification completes.
Core mail and chat remain available.

`POST /v1/apps/{app_id}/reverify?team_id=...` takes
`{"expected_generation":1}` and queues a verification job, returning `202`.
The verifier fetches outside the request and installation transaction, then
checks that the same pending identity/generation/digest is still current.
Matching bytes activate it without changing scopes, identity or generation.
A mismatch or fetch failure leaves it pending and records a bounded error code.
The admin surface displays that reason and offers another re-verify action.
A worker runs `aweb run-installation-verifications` periodically to process the
queue; the job pin is checked again before activation.

## Member requests and retirement

An ordinary member's install refusal offers the explicit admin-request flow.
The request stores a previewed app identity, origin, digest and requested scopes;
it grants no authority. The admin previews the pinned request and explicitly
confirms its granted scopes through the same origin verification and policy
checks. A changed origin response requires another preview before approval.
`POST /v1/apps/requests` takes `app_id`, `origin`, `digest` and
`requested_scopes`, all pinned to a server origin fetch, and returns a pending
`request_id` with status 201. It grants no tools or scopes. `aw plugin request
<origin>` uses this path and leaves local tools unchanged.

`GET /v1/apps/requests` returns the caller's requests; `?mine=false` requires
install-admin authority and returns the team's requests. The response is
`{"team_id":"...","requests":[...]}` with request identity, pin, scopes,
requester, state and resulting installation identity if approved.

`POST /v1/apps/requests/{request_id}/approve` takes `granted_scopes` and an
optional `expected_generation` (required when updating an existing installation).
It checks admission before fetching and current final policy, with the verified
origin, in the write transaction. The origin must still serve the request's pin, and selected scopes
must be a subset of the request. Approval and installation commit together.
`POST /v1/apps/requests/{request_id}/decline` resolves a pending request without
installing anything. Both refuse an already resolved request with
`409 installation_request_resolved`.

Uninstall is `POST /v1/apps/{app_id}/uninstall?team_id=...` with
`{"expected_generation":1}`. It locks the same current installation row as
other installation writes, checks `InstallAdminPolicy` with action
`apps.uninstall` (without an origin), and requires an exact current positive
BIGINT generation. Non-admins receive `403 admin_required`, an absent
installation `404 installation_not_found`, a stale generation
`409 generation_conflict`, and missing or invalid generations `422`.

The writing transaction calls
`aweb.installations.cleanup_installation_on(tx, *, installation)` under the
current installation row lock, before changing state. This single cleanup seam
retires live hook bindings; a cleanup failure rolls back the entire uninstall.
The app-request task service, when introduced, adds installation-scoped request
cancellation and claim release here in the same transaction. Cleanups never
commit, open another transaction or suppress failures.

Uninstall sets `state: "uninstalled"` and allocates a higher generation, making
older confirmations conflict. Repeating uninstall at the returned generation is
idempotent. It fetches nothing from the app origin. It retains the
installation and purpose-key history needed for authenticated status and scoped
lifecycle reporting. It does not delete app content.

Before confirmation, management reads show the pinned lifecycle declarations
and explicitly distinguish app-reported status from unavailable reporting.
A missing report is not an empty dataset or zero outstanding work. The detailed
lifecycle-report response shape remains to be finalized with its reporter.

`aw plugin uninstall <app-id> [--expected-generation N]` acts on the selected
team's server installation. Without the flag it reads the current generation
then sends one conditional uninstall; conflicts are surfaced without retry.
Local cached bytes and approvals remain available to other teams.
`aw plugin remove <name>` removes local bytes or this resident's local approval;
it does not uninstall the team's server installation.

The disposable real-stack consumer proof is
`FOLIO_UNINSTALL_PROOF=1 scripts/e2e-folio-wakes.sh`. It asserts refusal of an
existing read-only presentation and open edit session after uninstall and after
reinstall; a consumer that still serves them fails this acceptance.

On commit the server refuses ordinary app-event and hook-resolve credentials
and retires live hook bindings. `app-grant-read` deliberately keeps answering
with typed `state: "uninstalled"`, so the app can observe the end. The grant answer also
includes `installed_at`, the UTC creation time of that `installation_id`.
A re-pin preserves it; uninstall preserves it for lifecycle reporting, and a
reinstall creates a new ID and creation time. The shared `GrantStatus` parser
requires this typed UTC timestamp; it never substitutes an observation time.

App-side tool authorization stops within the advertised grant-status
`max_age_seconds` (at most 60 seconds) plus one refresh deadline (5 seconds
with the shared runtime defaults). A hosted tool gateway also has its own
origin-and-digest tool cache; its maximum lifetime must be included in the
host's uninstall bound and proved by that gateway's integration tests. This
server's grant-status lifetime does not establish the gateway's cache lifetime. Work already
committed is reconciled, never reported as rolled back. A reinstall cannot
revive the old ID's roles, links, approvals or app requests.


## CLI upgrade and replacement approval

Origin-only local consent and app-tool snapshots without `installation_id`
are not adopted. Default mint still grants core communication, but omits each
unbound or stale app with a named reason and the selected resident/team's
explicit recovery command. `aw plugin list` identifies apps that need approval
for this team's installation. Local cached bytes and another team's approvals
remain intact.

An upgraded custody service refuses app signing from an unbound snapshot
(`app_installation_required`), an inactive installation
(`app_installation_inactive`), or a replacement (`app_installation_changed`).
Its diagnostic gives both recovery steps; it never includes grant material.
An already-issued grant's ordinary coordination scopes continue working.
A running old custody process retains its loaded behavior until restarted.

For each affected selected resident and team:

1. Restart that resident's custody service under its harness with the upgraded
   binary: `aw --identity-home <resident-credential-dir> custody stop`, then
   `aw --identity-home <resident-credential-dir> custody serve`.
2. Explicitly approve the current installation:
   `aw --identity-home <resident-credential-dir> --team <team-id> plugin install <existing-app-origin>`.
   Joining an existing active pin needs no install-admin authority and does not
   change that team's installation.
3. Mint a fresh worker grant:
   `aw --identity-home <resident-credential-dir> --team <team-id> id grant mint --bundle normal-agent --ttl 1h --custody-socket auto --out <new-empty-grant-home>`.
   Relaunch the worker with `AWEB_IDENTITY_HOME` pointing to the new grant home.
   The old snapshot is not repaired in place.

Effective app approvals are scoped to exact team/app/installation ID.
An explicit `--app-tool app:verb` at mint only narrows that approved catalog;
it cannot approve a missing or replaced installation. Run `aw plugin install
<origin>` for the selected team before minting either an explicit or default
app-tool grant. A re-pin
keeps that ID, so existing consent and immutable tool snapshots keep working;
it never adds new tools to an old snapshot. Uninstall/reinstall changes the ID,
so old snapshots remain refused even at the same origin and digest. Explicit
reapproval and a fresh grant are required for the replacement.

The uninstall server/CLI change and Folio's tool, presentation and edit-session
installation fence land in the same train and ship in the same release. The
combined real-stack uninstall proof must pass before that train can land.


Folio consumes `NaappRuntime.installation_grants()` and its shared SQL
`installation_fence()` for member tools, read-only presentations and edit
sessions. These surfaces fail closed when the installation is inactive or its
pin cannot authenticate app-grant-read. Existing presentations and sessions
remain usable across a re-pin of the same installation ID; a replacement ID
never revives them. New links and sessions persist the current installation ID.

Folio migration 003 adds nullable installation IDs without network access.
A legacy row binds on its first verified, fresh, active grant observation only
when the installation's `installed_at` is strictly earlier than the row's
`created_at`. This preserves a pre-deploy capability created under the still
current installation. An older row, including equality, is refused permanently;
that refusal is committed and never retried against another installation.
This rule assumes comparable clocks across the server and Folio databases;
clock skew between those databases is a theoretical boundary of the rule.

Deploy the server carrying the creation-time grant field first, then Folio with
its required purpose-bound app-grant-read key, then re-pin every Folio
installation to the new manifest digest. Until the re-pin, the old pin refuses
G1 and Folio denies access. The manifest/key transition is shared with records;
records uses the same runtime grant source and fence. There is no second cache
or deployment-manifest fallback. A cached inactive observation may also deny a
fresh reinstall until the advertised grant-status freshness window expires.
