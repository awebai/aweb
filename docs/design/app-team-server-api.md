# App → team-server API: discovery, app read credentials, grant status, hook resolution

Status: **design of aweb-acgh.7 (D1 task G1), with what main implements**,
accepted under Juan's delegation (decisions 3, 9 and 10). Anything unmarked is
on main. Text that is not carries a bold lead-in: **Open (task)** for decided
work not on main, **In flight (task)** for work partly on main, and **After
the first release (task)** for decided work deliberately parked. The
task-level status is in the [build plan](app-team-server-api-build-plan.md).

This is the one generic contract by which an installed naapp reads from its
team's aweb coordination server. Three consumers share it:

- the B1 `GrantSource` (aweb-acgh.3), for which this is the remote source;
- aw-hooks target resolution (aweb-acgh.1, `docs/design/audit-substrate.md`
  §A4);
- pages / D1 (aweb-acgg), whose `docs/design/agent-pages.md` "Installation
  authority and scope" lists its requirements.

It is generic: no app names, no catalog semantics and no naapp-specific core
code. Where a hosted operator must act, this design states it as a generic
requirement on a custodial deployment.

## Summary for Juan

1. **Discovery is a signed artifact on the identity path.** No team record,
   certificate or DNS statement binds a team to its coordination server (§1).
   An `aweb.team-server/1` record does: the team controller signs it with the
   team key, AWID stores it with its signature and serves it anonymously, and
   the naapp verifies the signature itself against the current AWID team key.
   Juan approved this identity-path change (decision 3).
2. **A custodial deployment publishes for the teams it controls.** Where a
   deployment holds a team's controller key (Fully Hosted), that deployment
   signs and publishes the team's record, at team creation and on any move or
   key rotation. This is a generic requirement on a custodial deployment, and
   it is the same act a BYOT controller performs with `aw`. Until a team has a
   record, it does not resolve and naapps fail closed. No default origin
   exists anywhere.
3. **App credentials share one verifier.** The server verifies every app
   credential with one verifier and a fixed purpose table: `app-event`
   (released bytes), `app-grant-read`, `hook-resolve` and `app-request`. A
   purpose is accepted only from a key that the manifest bytes declare for
   it, and the server takes those bytes only from the app's declared origin;
   `event_emitters` keys stay `app-event` only.
4. **Grant status** is `GET /v1/apps/self/grant`: the calling app's own grant
   in the credential's team, with its `installation_id`, `generation` and
   state, `as_of` and `max_age_seconds ≤ 60`. Clients fail closed on expiry
   plus refresh failure. A digest change revokes the old digest's keys and
   grant at once. An uninstalled app still reads its grant and sees
   `uninstalled`.
5. **Hook resolution** is two reads keyed by
   `(team, catalog id, catalog version, hook)`. Each is authorized by the
   caller's own complementary binding, exactly as the hooks seat requires.
   The binding rows belong to the hooks lane and F6; this API reads them.

## Applicable model

- **Custody.** The naapp holds its own app private keys. The team controller
  holds the team key. For BYOT that is the customer's local `aw`. For Fully
  Hosted it is the hosted deployment. Members hold their identity keys.
- **Authority over the team**, its key, certificates and revocation, is the
  controller's, published at AWID (`docs/awid-sot.md`, "Teams" and
  "Certificates"; accepted decision
  `aweb/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md@b423415a92bf`).
- **Authority over an installation**, meaning its digest, scopes, keys and
  state, is the team server's installation row (`team_app_installs`, with the
  identity columns of
  `server/src/aweb/migrations/aweb/035_team_app_installation_identity.sql`).
  Only the team's current install admin writes it: install, update and
  uninstall require `require_install_admin`
  (`server/src/aweb/install_authority.py`, `server/src/aweb/install_admins.py`).
- **What the transport may do.** HTTPS authenticates a hostname, nothing more.
  A reachable server, a domain string, an invite's `server_url` or a
  caller-supplied URL establishes no authority over a team
  (`docs/invite-inspection.md`: the invite envelope is unsigned).
- **What the consumer verifies.** The naapp verifies (a) that the server origin
  is the one the current team key authorized, then (b) the server's grant
  answer over HTTPS from that origin. The server verifies the app's
  purpose-bound request signature against a key registered under the team's
  current installed digest.

## 1. Discovering the team's coordination server

### Why existing records are not authority

| Candidate | Why it is not authority over (team → server) |
| --- | --- |
| Team record, team certificate, certificate status | None carries a server field (`docs/awid-sot.md`, "Identity operations" and "Teams"). |
| `_awid.<domain>` TXT | Binds the domain to its controller key and, optionally, its registry, not to a coordination server (`awid/src/awid/dns_verify.py`, module docstring). |
| Namespace `default_delivery_origin` | Per namespace, not per team, and defined as messaging-only (`awid/src/awid_service/migrations/002_namespace_delivery_origin.sql`). AWID verifies the controller signature at write but stores only the origin, not the signature (`awid/src/awid_service/routes/dns_namespaces.py`), so a reader cannot check it. |
| Invite `server_url`, hosted sibling `server_url`, `workspace.yaml` `aweb_url` | Unsigned client configuration (`docs/invite-inspection.md`; `docs/byot-onboarding-contract.md`). |
| `aw`'s fallback | `aw init` falls back to `DefaultAwebURL` (`https://app.aweb.ai`, `cli/go/cmd/aw/helpers.go`) when no aweb URL is given (`awebURLOrDefault` in `cli/go/cmd/aw/init.go`). That is precisely the implicit hosted default this contract must not inherit. |

### The artifact: `aweb.team-server/1`

The team controller signs, with the team key:

```text
signing bytes = "aweb.team-server/1\n" || canonical_json(record)
record = {
  "v": 1,
  "type": "aweb.team-server",
  "team_id": "<name>:<domain>",
  "team_did_key": "<did:key of the team key that signs>",
  "server_url": "https://coord.example.com/api",
  "issued_at": "<RFC 3339 UTC>"
}
```

- `server_url` is the base URL that apps call: an `https` origin plus an
  optional path prefix, in canonical form (lower-case scheme and host, no
  default port, no trailing slash, no userinfo, query or fragment), at most
  2048 bytes. `http` is allowed only for loopback hosts, and a literal IP
  address only when it is loopback (`canonical_team_server_url` in
  `awid/src/awid/team_server_record.py`). The request audience is its origin
  (scheme://host[:port]). Signed request targets include the prefix
  (`aweb/aweb-protocol-expert/decisions/signed-request-target-is-the-external-path.md@b423415a92bf`).
- The signature has one accepted encoding: 86 characters of standard base64
  whose last character is `A`, `Q`, `g` or `w`.
- The domain-separation prefix keeps these bytes from being confused with a
  team certificate or an `aweb.owner-act/1`.
- **Publication.** `PUT /v1/namespaces/{domain}/teams/{name}/server` stores the
  record and signature (`publish_team_server` in
  `awid/src/awid_service/routes/teams.py`). AWID verifies the signature
  against the team's current key, refuses an `issued_at` that is not newer
  than the stored record (`409 not_newer`), and refuses one more than five
  minutes ahead of its clock, so a far-future record cannot pin the team. A
  record that does not verify against the team (a wrong or stale key, another
  team, a bad signature, a malformed record) gets the same `404` as an
  unknown team, so a publish never reveals that a private team exists. Other
  refusals are `422`. The body is bounded at 8 KiB, and publishing is
  rate-limited, with an exemption for a trusted service publisher.
  `GET` on the same path is anonymous for public and private teams alike, as
  certificate status is. It returns `{record, signature}` exactly as stored.
  Only the current record is served. Moving a team is a newer record.
- **Rotation.** Rotating the team key invalidates the old record, so the
  rotation carries the record re-signed with the new key in
  `resigned_records.team_server`, and AWID replaces it in the rotation's own
  transaction (decision 26; `docs/principal-attestation.md` §5, "Atomic
  path"; `awid/src/awid_service/attestation_rotation.py`). Verifiers never
  see the new key next to an old-key record. `aw id team rotate-key` always
  takes this path (`cli/go/cmd/aw/id_team_rotate_key.go`), and a custodial
  deployment must too (HO2). A rotation sent without `resigned_records`
  leaves the stored record on the old key; naapps then fail closed with
  `team_server_key_mismatch` until the controller re-publishes it.
- **Privacy.** The anonymous `GET` reveals a private team's server URL to
  anyone who knows the team id. Certificate status reveals only the team key.
  `GET` answers an identical `404` for an unknown team and for a team with no
  record, as certificate status does for unknown records. The disclosure is
  accepted (decision 9).
- **CLI.** `aw id team set-server --url <server_url>` signs locally with the
  team key under the existing controller custody, BYOT or local, and
  publishes. `aw id team show-server` reads and verifies. Both are generic
  (`cli/go/cmd/aw/id_team_server.go`).
- **Custodial deployments.** A deployment that holds a team's controller key
  publishes the record itself, with the same bytes and route, when it creates
  the team, and again whenever it moves the team or rotates its key.
  Publication may be a step in team creation. It never substitutes a default
  for a missing record. The deployment backfills its existing teams before any
  naapp depends on discovery, with no interim pin (decision 3).

### Trust chain the naapp checks

Input: a `team_id` used only as a lookup key. A naapp takes it from whatever
it already authenticated: a team certificate verified by B1, or the team of a
verified app or hook-delivery credential. Trust comes from steps 1 to 3, never
from the input. No URL, registry or server is ever taken from a request,
header, event or certificate.

1. **Registry.** The registry is the verifier's configured registry
   (`NaappSettings.awid_registry_url`), the same registry whose team key
   verified the certificate. Discovery reads the domain's `_awid.<domain>`
   statement and refuses with `registry_mismatch` when it names a different
   registry, rather than mixing two authorities for one team. A malformed,
   timed-out or failed lookup refuses with `authority_unavailable` and never
   falls back.
2. **Current team key** from that registry, read through B1's team cache
   (`AWIDTeamCache`), one instance per registry origin, not a second cache.
   AWID not knowing the team, or refusing its certificate status, refuses
   with `team_unknown`.
3. **Record.** `GET …/teams/{name}/server` from the same registry. Require
   `type`, `v` and `team_id` equal to the input. If `team_did_key` differs
   from the current team key, as after a rotation without the re-signed
   record, refuse with `team_server_key_mismatch`; the old record is never
   valid. Verify the Ed25519 signature over the signing bytes, and refuse an
   `issued_at` more than five minutes ahead of the client clock. Any other
   refusal of the record is `team_server_record_invalid`.
4. **Use.** Call only `server_url`, sign with `aud` set to its origin, and
   follow no redirects.
5. **Cache.** Key the cache on `(registry origin, team_id)`, reuse for at most
   60 s, and keep no expired fallback. A refresh failure returns
   `authority_unavailable`. A verified absent record returns
   `team_server_unpublished`. Every refusal fails closed, and the six codes
   stay distinct so operators can tell an outage, an unknown team, a missing
   record, an invalid record, an unpublished rotation and a registry mismatch
   apart (`TeamServerUnavailable` in
   `naapp-lib/src/aweb_naapp/runtime/team_server.py`).

The record's freshness rests on the selected registry, exactly as the team
key's does: this adds no new trust, only a signed statement under the trust
already placed in that registry.

The naapp also learns the app-side half of D1's rule here. It never accepts a
grant answer from any origin other than the one verified in step 3.

### Rejected alternatives

- **The server serves a team-key-signed record itself, with no AWID change.**
  Rejected. Nothing supersedes it: a server the team has left keeps a valid
  statement until the team key rotates. Adding expiry instead forces
  offline BYOT controllers to keep re-signing.
- **Reuse `default_delivery_origin`.** Rejected. It is per namespace, defined
  as messaging-only, and its signature is not retained. Redefining it would
  change a shipped contract.
- **A member-asserted server, for example from install or certificate
  presentation.** Rejected. A member is not the controller. One member could
  point an app at a server that grants whatever it likes.
- **An implicit hosted default.** Rejected by the task.
- **An operator-declared pin per namespace in the naapp's configuration.**
  Rejected. The naapp operator would assert authority over teams it cannot
  prove it controls, and a pin outlives a team that moves. With custodial
  deployments publishing records, nothing needs it.

## 2. App read credentials (purpose split)

### The app credential pattern

Every app credential has the form `Authorization: <prefix> <did:key> <sig>`
with a signed `auth` value. The released app-event credential is
`AWEB-App DIDKey …` with `auth: "app-event"`; `verify_app_event_auth`
(`server/src/aweb/app_events.py`) is a thin wrapper over the shared verifier.
The other credential types are told apart the same way, by an exact
`Authorization` prefix plus an exact `auth` value (`AWEB-Grant DIDKey ` with
`identity-grant`, `server/src/aweb/identity_grant_auth.py`).

### One verifier, four purposes

One server verifier, `verify_app_credential(request, db, purpose)`
(`server/src/aweb/app_credentials.py`), driven by a fixed purpose table:

| Purpose | `Authorization` prefix | `auth` | Key source |
| --- | --- | --- | --- |
| `app-event` | `AWEB-App DIDKey ` | `app-event` | a `team_app_emit_keys` row (acgh.8), or a `team_app_keys` row whose `purposes` contains `app-event` |
| `app-grant-read` | `AWEB-App-Grant-Read DIDKey ` | `app-grant-read` | `team_app_keys` row whose `purposes` contains it |
| `hook-resolve` | `AWEB-App-Hook-Resolve DIDKey ` | `hook-resolve` | `team_app_keys` row whose `purposes` contains it |
| `app-request` | `AWEB-App-Request DIDKey ` | `app-request` | `team_app_keys` row whose `purposes` contains it, plus the installation binding below |

- **Headers and signed payload** are those of app-emit v1
  (`docs/app-events.md`): `X-AWEB-App-ID`, `X-AWEB-App-Key-ID`,
  `X-AWEB-Team-ID`, `X-AWEB-Timestamp` and `X-AWEB-Signed-Payload`. The payload
  is canonical JSON of `{v: 1, auth, aud, method, path, team_id, app_id, kid,
  did_key, body_sha256, timestamp}`. The checks are the app-emit v1 checks:
  exact canonical form, 300 s skew, method, raw external path plus query,
  body hash, and `aud` equal to the server's configured `public_origin`.
- **One signature encoding for the newer purposes.** `app-grant-read`,
  `hook-resolve` and `app-request` accept only the strict encoding: 86
  characters of standard base64 whose last character is `A`, `Q`, `g` or
  `w`, so each signature has exactly one accepted form (Athena's ruling,
  recorded on aweb-acgh.17.5). `app-event` keeps the lenient decoder its
  released signers use.
- **Purpose binding is exact both ways.** The prefix selects the purpose, the
  signed `auth` must equal it, and the key must be registered for it. An
  `app-event` credential presented at a read endpoint is refused, and so is a
  read credential at `/v1/events/app`. The `app-event` bytes and the vector
  `app-emit-credential-v1.json` do not change.
- **The emit key stays emit-only by construction.** `event_emitters` rows live
  in their own table, and only the `app-event` purpose reads that table. A
  v2 `app_keys` entry may name the same physical `did_key` for several
  purposes, `app-event` among them (D1, "App keys are a generic,
  purpose-split set"), so a v2 app emits with an `app_keys` key. Each purpose
  is still verified separately.
- **Reads do not bind installation id or generation.** The grant read is how
  the app *learns* them. `app-request` binds them: its signed payload also
  carries `installation_id` and `installation_generation`, which must equal
  those of an active, origin-verified installation, or the request is
  refused with `403 scope_denied` (`docs/app-task-requests.md`).
- **`app-usage`.** The app builds `app-usage` credentials
  (`naapp-lib/src/aweb_naapp/runtime/usage.py`, `docs/app-usage.md` §4).
  **After the first release (aweb-acgh.18.19):** the server's usage
  reporting and its `app-usage` verifier (decision 88).
- **Errors.** `401` for a malformed, mismatched or unsigned credential. `403
  app_key_not_registered` when no key is active for that purpose under the
  current installed digest; `app-event` keeps its released detail, `App emit
  key is not registered`. A `hook-resolve`, `app-request` or `app-event` key
  is active only while the installation is `active` and origin-verified. An
  `app-grant-read` key stays valid in every installation state, so an app
  whose installation is pending or uninstalled still reads its grant (§3);
  it gets `403 app_key_not_registered` only when the installation row is gone
  or pinned to another digest.

### Key registration: keys come only from the origin's bytes

An app key is the app's own statement, so the server takes it only from the
manifest bytes it fetched from the app's declared origin, which hash to the
pinned digest. It never takes one from a field the installer fills in.
Otherwise any installer could pin an app's real origin and digest with keys
of its own. Every registration is a row of the installing team
(`team_app_emit_keys`, `team_app_event_types`, `team_app_keys`), a changed
`did_key` for a registered key id is refused, and revocation is one-way.

- **Install carries no bytes.** The install request is `app_id`, `origin`,
  `digest`, `granted_scopes` and `expected_generation`, with no `manifest`
  and no `app_keys` field, and unknown fields are refused (`AppInstallRequest`
  in `server/src/aweb/routes/apps.py`). The server fetches the exact bytes
  from the declared HTTPS origin through shared egress, requires them to hash
  to `digest`, and stores them on the installation (`manifest_bytes`,
  migration 035). Installer-uploaded bytes and separately supplied keys are
  not installation authority (`docs/app-registry.md`, "Install, update and
  management reads"). Naapps keep no backward compatibility for released
  `aw` clients (decision 44), so no install path accepts bytes or keys from
  the client.
- **The server reads the bytes** with the one manifest reader,
  `aweb_naapp.manifest.load_manifest` (decision 56): the bytes must parse
  strictly, and their `app.id` must equal the request's
  (`422 manifest_app_mismatch` otherwise). It reads
  `app_keys: [{kid, did_key, purposes}]` (v2, frozen by C3), or a v1
  manifest's `event_emitters` as `app-event` keys.
- **Rows are the installing team's.**
  `team_app_keys (team_id, app_id, origin, digest, key_id, did_key, purposes
  TEXT[], created_at, revoked_at)` (migration 027). As for emit keys, a key id
  keeps its first `did_key` within the team and app, a conflicting install
  gets `409`, and a revoked key stays revoked, across digests and manifest
  versions (`docs/app-registry.md`). The operator command
  `aweb reseed-app-registrations` recreates these rows from the bytes as
  well, and reports teams left unchanged by a `key_conflict`.
  **Open (aweb-acgh.17.19):** serializing concurrent registrations of one key
  id with different `did_key`s. Two such registrations racing can both pass
  the identity check; authentication then refuses the key, so the outcome is
  an unusable registration, not a usable conflicting key.
- **Labels.** A purpose label is a lower-case token. An unrecognized label is
  stored and grants nothing, which is D1's rule.
- **What this does not prove.** Matching a digest does not prove that the
  origin serves those bytes; the server's own fetch from the origin does. An
  installation whose bytes the server has not fetched from the origin stays
  `pending_origin_verification`, and confers no ordinary authority: the
  `active` state requires `origin_verified` and stored bytes (constraint
  `team_app_installs_active_verified`, migration 035), and every key lookup
  for ordinary authority requires an active, origin-verified installation
  (`server/src/aweb/app_registry.py`). Bytes the installer made therefore never
  sign events, requests or hook reads. What the fetch proves is only what the
  origin served over HTTPS at that time. Which origin and digest a team pins
  is the team's install admin's choice: the keys are those that origin
  declares, and the app id is whatever those bytes name. Owner activation of
  a hook binding separately compares the digest the owner's client fetched
  from the origin (audit-substrate §A3).
- **v1 has no read purposes.** v1 manifests declare no `app_keys` (strict v1
  rejects unknown fields, `docs/app-manifest.md`, "Top-level structure"), so
  read purposes exist only for v2 installs.

### Per-team key revocation

**Open (aweb-acgh.17.6):** a team's install authority, meaning F6's admin
policy, may revoke one key for its own team at once, without waiting for a
new digest: `POST /v1/apps/{app_id}/keys/{kid}/revoke`, with ordinary team
auth. It sets the team row's `revoked_at`, which is one-way. **Open
(aweb-acgh.17.7):** the revoke also enqueues the post-mutation-hook event
`app_key.revoked` (payload `app_id`, `kid`, `purposes`; the envelope carries
`team_id` and the actor) in the same transaction, because which events a
target accepts is audit-relevant (audit-substrate §A6). The hooks catalog is
a strict allowlist, so this depends on `app_key.revoked` staying in
audit-substrate §A10's v1 mutation types and in the hook-catalog and
post-mutation-hook-sites vectors (§A10 and §A11). Key rows are the team's
own, so one team can never disable an app for another. Revocation for every
team is the app's own act: it publishes new bytes, and each team installs the
new digest.

## 3. Grant status

```http
GET /v1/apps/self/grant
Authorization: AWEB-App-Grant-Read DIDKey <did:key> <sig>
```

The team and app come from the verified credential, never from a query
parameter, so an app can read only its own grant
(`app_grant_status_route` in `server/src/aweb/routes/apps.py`).

```json
{
  "team_id": "backend:acme.com",
  "app_id": "notes",
  "state": "active",
  "origin": "https://notes.example",
  "app_version": "1.4.0",
  "manifest_version": 2,
  "digest": "sha256:…",
  "granted_scopes": ["notes:read"],
  "installation_id": "3f0c…",
  "generation": 3,
  "origin_verified": true,
  "installed_at": "2026-10-19T11:58:02Z",
  "as_of": "2026-10-19T12:00:00Z",
  "max_age_seconds": 60
}
```

- **`installation_id` and `generation`** are always present: every
  installation row carries both (migration 035). A reinstall creates a new
  `installation_id`. `generation` strictly increases per `(team, app)` across
  installation ids, allocated from a counter row that is never deleted, so it
  survives a full uninstall and is never reset (decision 51). Consumers order
  installations by generation.
- **`state`** is one of `pending_origin_verification`, `active` and
  `uninstalled`. Every state other than `active` grants no normal use.
  Uninstall keeps the pin and the keys, so an app observes its own confirmed
  uninstall as `200` with `state: uninstalled`.
- **`origin_verified`** says whether the server fetched the pinned bytes from
  the origin; `installed_at` is when this installation was created.
- **`max_age_seconds`** is configuration with a ceiling of 60 s. It is also the
  bound the hooks lane pads `active_from` with (audit-substrate §A3, §A4.4).

### Client semantics (the remote `GrantSource`)

| Server outcome | GrantSource result | B1 maps it to |
| --- | --- | --- |
| `200`, `state: active`, fresh | grant | scope check, then app policy |
| `200`, state other than `active` | not granted | `403 scope_denied` (no grant) |
| `403 app_key_not_registered` | not granted | `403` (no grant) |
| discovery refused (§1, any of the six codes) | unavailable | `503 authority_unavailable` |
| timeout, `5xx`, TLS failure, malformed answer, cache past `max_age` with refresh failing | unavailable (`grant_refresh_timeout`, `grant_server_unreachable`, `grant_answer_malformed`) | `503 authority_unavailable` |

- A positive answer is reused for at most `min(max_age_seconds, 60)`, counted
  from when the client asked: the start of the refresh that fetched it. There
  is no stale fallback.
- An expired entry is never served, including while a refresh is in flight.
  Each refresh has a request timeout (configuration, default 5 s). A caller
  waiting on it receives unavailable when it fires, so the staleness bound is
  `max_age_seconds` itself, with no unbounded refresh on top.
- A definitive "not granted" may be cached for the same window, except
  `403 app_key_not_registered`, which is cached for at most five seconds so
  an immediate post-install retry does not retain a minute-long denial.
- Concurrent misses for one `(team, app)` share one refresh.

### Revocation bound, stated honestly

A change on the server reaches every naapp within `max_age_seconds` plus the
time for one refresh (decision 37):

- **Digest change (reinstall with new bytes).** Immediate on the server: keys
  are digest-scoped, so the old digest's read keys stop verifying, and the
  grant answer shows the new digest and scopes.
- **Uninstall, reinstall and generation change.** The answer flips state, or
  its `installation_id` and `generation`, on the next read. A short cache is
  not an admission fence, so F6's fence remains the guarantee against
  admitting work under an obsolete generation. This API gives the
  bounded-staleness half.
- **Per-team key revocation.** **Open (aweb-acgh.17.6):** a revoked key stops
  verifying on the next credential check (§2).

## 4. Hook resolution

Shaped with the aw-hooks seat (audit-substrate §A4). Both reads use the
`hook-resolve` credential (`server/src/aweb/routes/app_hooks.py`):

```http
GET /v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/registrations
GET /v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/productions
```

- **Registrations** answer the producer's question: where to deliver. They are
  allowed only while the caller holds an active production for that exact
  hook in the credential's team.
- **Productions with keys** answer the target's question: whether a producer
  is approved, and with which key. They are allowed only while the caller
  holds an active registration for that hook.
- **Own bindings.** `GET /v1/apps/self/hooks/bindings?binding_id=<id>` or
  `?hook=<catalog_id>/<catalog_version>/<hook>` returns the caller's own
  bindings of both kinds, in every state, so a target can confirm that the
  `binding_id` a delivery names is its own active registration
  (audit-substrate §B2, step 2). Exactly one of `binding_id` and `hook` is
  accepted; anything else is `400`.
- **Response.** Each binding carries `binding_id`, `kind`, `app_id`,
  `installation_id`, `generation`, `origin`, the resolved `method` and raw
  `path`, `digest`, and `active_from`. Own bindings also carry `catalog`,
  `hook`, `state`, `ended_by`, `activated_at` and `revoked_at`. Productions
  also carry the producer's active keys of that generation whose declared
  purposes include `hook-event` or `hook-delivery`, each as
  `{kid, did_key, purposes}`; an emit-only or usage key is never listed. The
  response envelope carries `as_of` and `max_age_seconds` (≤ 60).
- **Historical verification.** Responses list currently active keys only.
  Verifying an event after its producer's key was retired relies on the key
  evidence the target records at ingest (logs' ingest record, audit-substrate
  §B2). This API keeps no key history for apps.
- **A refused read** returns `403 hook_binding_required`. An unknown catalog
  id, version or hook resolves to nothing, and is reported as `200` with an
  empty list only when the caller holds the complementary binding. That
  binding cannot exist for an unknown hook, so in practice the answer is
  `403`.
- **Client-class hooks.** **Open (aweb-acgh.17.18):** a member authenticated
  by ordinary team-auth v2 may list registrations for client-class hooks
  only, through the same path with the member envelope. This is how `aw`
  finds `post-command-hook` targets. Every resolution route refuses a member
  envelope with the same `401` as any credential that is not `hook-resolve`.
- **The core producer's keys.** `GET /v1/hooks/producer-keys`, anonymous on
  the discovered server URL, returns `{keys: [{kid, did_key, valid_from,
  valid_until|null}], as_of, max_age_seconds}`, retired keys included. These
  are operator configuration, never a team, controller or agent key. A
  consumer anchors the core origin per team through the §1 chain, at install
  or first resolution, and caches it under §1's rules. It never takes an
  origin from an event or a request. When the team's `aweb.team-server/1`
  record changes, the consumer re-resolves; events received before the change
  keep verifying from the key evidence recorded at their ingest.
  **After the first release (aweb-acgh.16.32):** [terminal
  delivery](../hook-terminal-delivery.md) additionally requires a
  delivery-carried exact-event/old-target capsule; this key listing alone
  never authorizes an ended binding. Historical event and capsule windows
  differ from the current retry signer’s validity. No own-bindings or
  installation-read authority is restored after uninstall.
- **Client.** The client keeps a cache of at most 60 s and fails closed on
  expiry plus refresh failure, as grant status does.
- **Dependency.** Bindings are child rows of the installation (the hooks
  lane's `app_hook_bindings`, migration 032, keyed by `installation_id`).
  This API reads them. It does not define binding state or activation.

## 5. Client in `aweb_naapp.runtime`

Placed under the `runtime` extra, which depends on `awid-service` and `httpx`
(`naapp-lib/pyproject.toml`). The runtime builds one `TeamServerDirectory`
and one `HookResolver` and shares them (`NaappRuntime.team_server_directory`,
`NaappRuntime.hook_resolver`; decision 69):

- `TeamServerDirectory` (`runtime/team_server.py`):
  `resolve(team_id, certificate_id=None) -> TeamServer(team_id, server_url, audience, team_did_key, expires_at)`,
  implementing the §1 chain. It reuses the same registry selection and
  team-key cache as B1's verifier rather than a second copy.
- `AppCredentialSigner(*, app_id, key, purpose)` (`runtime/app_credentials.py`):
  signs one purpose with an `AppKey` (kid, `did_key` and signing key) from
  the single app-key loader, `load_app_key` (`runtime/app_keys.py`):
  - **Configuration names keys by kid**: a map from kid to key file. Which
    purposes a kid may sign comes from the pinned manifest's `app_keys`, not
    from configuration, so the key for a purpose is the configured kid the
    manifest declares for it, and the loader refuses at startup when there is
    none.
  - **One reader**, `aweb_naapp.signing_key` behind the dependency-light
    `signing-key` extra (`pynacl` only), so that core can load its own
    hook-producer key with it too, runs once at startup and fails startup on
    a missing, unreadable or malformed key. No naapp parses key bytes itself.
  - **File checks** (`aweb_naapp.key_file.read_key_file`): a regular file, not
    group- or world-writable. Read bits are left to the platform, because
    standard mounted secrets (Kubernetes 0644, Docker 0444, platform secret
    files) are world-readable inside a single-user container.
  - **One format**: 64 lowercase or uppercase hex characters (the Ed25519
    seed), with one trailing newline allowed.
  - **Never logged**: key material appears in no log, error, repr or
    settings dump, and a test proves it.
  - **Released value form**: the per-app `*_APP_EMIT_KEY_SEED_HEX` setting
    stays accepted for the `app-event` key only, read by the same loader,
    until it is measured that no deployment uses it, and is never extended to
    new purposes (decision 10). It is deploy configuration, so decision 44
    leaves it in place.
- `TeamGrantSource` (`runtime/team_grants.py`): the remote implementation of
  B1's `GrantSource` (`aweb_naapp.runtime.authorization`), using
  `async grant_for(team_id, certificate_id=None) -> Grant | None`:
  - member admission passes the already verified principal's certificate ID
    through to discovery, so the shared AWID cache can read per-certificate
    status when the app has no AWID service token;
  - an active installation of this app returns
    `Grant(team_id, scopes, fresh_until, installation_id, generation)`, where
    `fresh_until` is the client's monotonic time when it asked plus
    `min(max_age_seconds, 60)`;
  - an inactive state or `app_key_not_registered` returns `None`, which B1
    maps to `403`;
  - a discovery refusal, an outage, a timeout or a malformed answer raises
    `GrantUnavailable`, which B1 maps to `503 authority_unavailable`.

  `status_for(team_id, certificate_id=None)` shares that read and cache and
  returns a typed `GrantStatus` with every answer field, inactive and unknown
  states preserved; an unknown state disables use. A `None` from a missing
  key is never proof of uninstall (decision 48b). The source itself checks
  the answer's `app_id`, `origin` and `digest` against the app's own identity
  before returning a grant.
- `HookResolver` (`runtime/hook_resolver.py`): `registrations(team_id,
  catalog, version, hook)`, `productions(…)`, `own_bindings(…)` and
  `core_producer_keys(team_id)`, with the §4 semantics.

## 6. Build split

The [build plan](app-team-server-api-build-plan.md) carries each task's
board id and status.

| Step | Contents | Status |
| --- | --- | --- |
| G1-a | AWID `aweb.team-server/1`: migration, PUT/GET routes, `aw id team set-server/show-server`, conformance vector `docs/vectors/team-server-record-v1.json` | on main (decision 3) |
| G1-a′ | Custodial deployment publishes and backfills records for the teams whose controller key it holds | hosted operator's build (aweb-acgg.31) |
| G1-b | Server: generalized purpose verifier (app-event unchanged and vector-checked), `team_app_keys`, keys from origin-fetched bytes, `GET /v1/apps/self/grant`, vector `test-vectors/app-read-credential-v1.json` | on main, except per-team key revocation: **Open (aweb-acgh.17.6, aweb-acgh.17.7)** |
| G1-c | `aweb_naapp.runtime`: directory, signer, `TeamGrantSource` | on main |
| G1-d | Hook resolution endpoints including own bindings, producer keys, `HookResolver` | on main, except the member path: **Open (aweb-acgh.17.18)** |
| G1-e | Real-stack acceptance | **Open (aweb-acgh.17.13, aweb-acgh.17.14)** |

Each step is TDD with tests in both directions. Server tests run on real
Postgres through the existing pgdbm fixtures (`server/tests/conftest.py`).
AWID tests run against a real AWID service. Signatures come from the
conformance vectors, not mocks. The real-stack check extends the existing
Docker e2e harness, with AWID, aweb and one fixture naapp.

## Decided questions

1. **The `aweb.team-server/1` identity-path change** (§1): an AWID schema and
   route, signed by the team key. Approved (decision 3). It is the only option
   where the controller authorizes the binding and a newer record supersedes
   an older one.
2. **Existing teams of custodial deployments.** Teams created before the
   record existed need a one-time publication by the deployment that holds
   their controller key; until it runs, they fail closed at naapps. The
   custodial deployment backfills records for its existing teams before any
   naapp depends on discovery, with no interim pin (decision 3).
3. **Ownership of installation identity.** F6 owns `installation_id`,
   generation, state and uninstall (migration 035); this API reads
   them.
4. **Disclosure of a private team's server URL** (§1, Privacy). Anyone who
   knows a private team's id can read its coordination server URL;
   certificate status discloses only the team key. Accepted (decision 9): a
   server URL is not a credential, every request to it is still
   authenticated, and an authenticated read would leave a naapp unable to
   discover a team before it can authenticate to it.
5. **One rule for loading app keys** (§5): one loader for every app key and
   purpose, reading key files named by kid; the released seed-value setting
   stays accepted for the `app-event` key only until it is measured that no
   deployment uses it, and is never extended to new purposes (decision 10).
   If a platform that can only supply environment values appears, extending
   the value form would be Juan's decision.
