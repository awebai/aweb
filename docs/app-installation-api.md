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
admin authority inside the mutation transaction. The named refusal is
`403` with `detail.code: "admin_required"`; another team's context gets `404`.
Ordinary members can preview and request an installation, without granting use.

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

Every successful confirmation returns the installation record. It stores the
fetched bytes and their digest, sets `state: "active"` and
`origin_verified: true`, and derives registrations from those bytes. New hook
registrations and productions remain pending their owner's separate activation.
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
It checks current admin policy before fetching and again in the write
transaction. The origin must still serve the request's pin, and selected scopes
must be a subset of the request. Approval and installation commit together.
`POST /v1/apps/requests/{request_id}/decline` resolves a pending request without
installing anything. Both refuse an already resolved request with
`409 installation_request_resolved`.

Uninstall is `POST /v1/apps/{app_id}/uninstall?team_id=...` with
`{"expected_generation":1}`. It locks the same current installation row as
app-task admission, checks admin authority and generation, marks it uninstalled,
revokes normal authority and cancels all still-open app requests in that same
transaction through the task service's cancellation hook. It retains the
installation and purpose-key history needed for authenticated status and scoped
lifecycle reporting. It does not delete app content.

Before confirmation, management reads show the pinned lifecycle declarations
and explicitly distinguish app-reported status from unavailable reporting.
A missing report is not an empty dataset or zero outstanding work. The detailed
lifecycle-report response shape remains to be finalized with its reporter.

Normal use stops within the grant/fence freshness contract. Work already
committed is reconciled, never reported as rolled back. A reinstall cannot
revive the old ID's roles, links, approvals or app requests.
