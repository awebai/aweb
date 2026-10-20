# App → team-server API: discovery, app read credentials, grant status, hook resolution

Status: **design proposal, aweb-acgh.7 (D1 task G1)**, amended after fit
review by the D1 lead and the aw-hooks seat, an independent review and Athena;
awaiting their re-review, then Juan. Nothing here ships yet. Baseline is
`origin/main` at `b423415a9`; source citations are at that commit unless marked
acgh.8, which cites the team-scoped app registrations on
`agents/aweb-protocol-expert-app-team-api-emit-keys@a7ee9f186` (under review).

This is the one generic contract by which an installed naapp reads from its
team's aweb coordination server. Three consumers share it:

- the B1 `GrantSource` (aweb-acgh.3), for which this is the remote source;
- aw-hooks target resolution (aweb-acgh.1, `docs/design/audit-substrate.md`
  §A4 at `23a88a8ad`);
- pages / D1 (aweb-acgg), whose `agent-pages.md` §5 "Installation authority
  and scope" at `1fb0fafcb` lists its requirements.

It is generic: no app names, no catalog semantics and no naapp-specific core
code. Where a hosted operator must act, this design states it as a generic
requirement on a custodial deployment.

## Summary for Juan

1. **Discovery needs a new signed artifact, an identity-path change.** Today no
   signed record binds a team to its coordination server (§1). Recommendation:
   an `aweb.team-server/1` record that the team controller signs with the team
   key. AWID stores it with its signature and serves it anonymously. The naapp
   verifies the signature itself against the current AWID team key. This is a
   new AWID migration and route plus an `aw` command, and needs your explicit
   approval and Athena's review.
2. **A custodial deployment publishes for the teams it controls.** Where a
   deployment holds a team's controller key (Fully Hosted), that deployment
   signs and publishes the team's record, at team creation and on any move or
   key rotation. This is a generic requirement on a custodial deployment, and
   it is the same act a BYOT controller performs with `aw`. Until a team has a
   record, it does not resolve and naapps fail closed. No default origin
   exists anywhere.
3. **App reads use new purposes over the same verifier.** The server
   generalizes the shipped app-emit verifier into one verifier with a fixed
   purpose table: `app-event` (unchanged bytes), `app-grant-read` and
   `hook-resolve`. A purpose is accepted only from a key the pinned manifest
   bytes declare for it; `event_emitters` keys stay `app-event` only.
4. **Grant status** is `GET /v1/apps/self/grant`: the calling app's own grant
   in the credential's team, with `as_of` and `max_age_seconds ≤ 60`. Clients
   fail closed on expiry plus refresh failure. A digest change revokes the old
   digest's keys and grant at once. Uninstall and generation follow when F6
   adds them.
5. **Hook resolution** is two reads keyed by
   `(team, catalog id, catalog version, hook)`. Each is authorized by the
   caller's own complementary binding, exactly as the hooks seat requires. The
   binding storage belongs to the hooks build and F6, so this lane builds the
   read side once that table exists.

## Applicable model

- **Custody.** The naapp holds its own app private keys. The team controller
  holds the team key. For BYOT that is the customer's local `aw`. For Fully
  Hosted it is the hosted deployment. Members hold their identity keys.
- **Authority over the team**, its key, certificates and revocation, is the
  controller's, published at AWID (`docs/awid-sot.md:463`–`:516`, `:583`–`:597`;
  accepted decision
  `aweb/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md@b423415a92bf`).
- **Authority over an installation**, meaning its digest, scopes and keys, is
  the team server's registry row
  (`server/src/aweb/migrations/aweb/008_app_registry_grants.sql:42`–`:60`),
  written by an authenticated member today and by an admin after F6.
- **What the transport may do.** HTTPS authenticates a hostname, nothing more.
  A reachable server, a domain string, an invite's `server_url` or a
  caller-supplied URL establishes no authority over a team
  (`docs/invite-inspection.md:47`–`:50`).
- **What the consumer verifies.** The naapp verifies (a) that the server origin
  is the one the current team key authorized, then (b) the server's grant
  answer over HTTPS from that origin. The server verifies the app's
  purpose-bound request signature against a key registered under the team's
  current installed digest.

## 1. Discovering the team's coordination server

### What exists (and why none of it is enough)

| Candidate | Why it is not authority over (team → server) |
| --- | --- |
| Team record, team certificate, certificate status | None carries a server field (`docs/awid-sot.md:484`–`:487`, `:512`–`:516`, `:652`–`:666`, `:583`–`:597`). |
| `_awid.<domain>` TXT | Binds the domain to its controller key and, optionally, its registry, not to a coordination server (`awid/src/awid/dns_verify.py:4`). |
| Namespace `default_delivery_origin` | Per namespace, not per team, and defined as messaging-only (`awid/src/awid_service/migrations/002_namespace_delivery_origin.sql:2`–`:3`). AWID verifies the controller signature at write but does not retain it (`awid/src/awid_service/routes/dns_namespaces.py:370`–`:425`), so a reader cannot check it. |
| Invite `server_url`, hosted sibling `server_url`, `workspace.yaml` `aweb_url` | Unsigned client configuration (`docs/invite-inspection.md:47`–`:59`; `docs/byot-onboarding-contract.md:74`–`:79`). |
| `aw`'s fallback | `cli/go/cmd/aw/init.go:826`–`:831` maps "registry is api.awid.ai" to "server is app.aweb.ai/api". That is precisely the implicit hosted default this contract must not inherit. |

### Proposed artifact: `aweb.team-server/1`

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
  optional path prefix, with no userinfo, query or fragment. `http` is allowed
  only for localhost in development, matching AWID's delivery-origin rule
  (`awid/src/awid_service/delivery_origin.py:31`–`:56`). The request audience
  is its origin (scheme://host[:port]). Signed request targets include the
  prefix
  (`aweb/aweb-protocol-expert/decisions/signed-request-target-is-the-external-path.md@b423415a92bf`).
- The domain-separation prefix keeps these bytes from being confused with a
  team certificate or an `aweb.owner-act/1`.
- **Publication.** `PUT /v1/namespaces/{domain}/teams/{name}/server` stores the
  record and signature. AWID verifies the signature against the team's current
  key, refuses an `issued_at` that is not newer than the stored record, and
  refuses one more than five minutes ahead of its clock, so a far-future
  record cannot pin the team.
  `GET` on the same path is anonymous for public and private teams alike, as
  certificate status is (`docs/awid-sot.md:583`–`:597`). It returns
  `{record, signature}` exactly as stored. Only the current record is served.
  Moving a team is a newer record. Rotating the team key invalidates the old
  record, so rotation re-signs and publishes the record in the same
  operation: in `aw`'s rotate flow for BYOT, and in the same step for a
  custodial deployment. A publish that fails after rotation is reported and
  retried, because publishing is idempotent. Until it succeeds, naapps fail
  closed for that team.
- **Privacy.** The anonymous `GET` reveals a private team's server URL to
  anyone who knows the team id. Certificate status reveals only the team key.
  `GET` answers an identical `404` for an unknown team and for a team with no
  record, as certificate status does for unknown records
  (`docs/awid-sot.md:583`–`:597`). The disclosure is open question 4.
- **CLI.** `aw id team set-server --url <server_url>` signs locally with the
  team key under the existing controller custody, BYOT or local, and
  publishes. `aw id team show-server` reads and verifies. Both are generic.
- **Custodial deployments.** A deployment that holds a team's controller key
  publishes the record itself, with the same bytes and route, when it creates
  the team, and again whenever it moves the team or rotates its key.
  Publication may be a step in team creation. It never substitutes a default
  for a missing record.

### Trust chain the naapp checks

Input: a `team_id` used only as a lookup key. A naapp takes it from whatever
it already authenticated: a team certificate verified by B1, or the team of a
verified app or hook-delivery credential. Trust comes from steps 1 to 3, never
from the input. No URL, registry or server is ever taken from a request,
header, event or certificate.

1. **Registry.** Select the registry for the team's domain: the
   `_awid.<domain>` statement's registry, or the canonical public registry
   when no statement exists. A malformed, duplicate, timed-out or failed
   lookup refuses and never falls back (`docs/awid-sot.md:279`–`:287`;
   `awid/src/awid/dns_verify.py:57`–`:66`). This must be the same registry
   whose team key verified the certificate. If the verifier is configured
   with a single registry, discovery uses that registry and refuses a domain
   whose `_awid` statement names a different one, rather than mixing two
   authorities for one team.
2. **Current team key** from that registry, read through B1's team cache
   (`AWIDTeamCache`), one instance per registry origin, not a second cache.
3. **Record.** `GET …/teams/{name}/server` from the same registry. Require
   `type`, `v` and `team_id` equal to the input. If `team_did_key` differs
   from the current team key, as after a rotation that has not yet been
   re-published, refuse with `team_server_key_mismatch`; the old record is
   never valid. Verify the Ed25519 signature over the signing bytes, and
   refuse an `issued_at` more than five minutes ahead of the client clock.
4. **Use.** Call only `server_url`, sign with `aud` set to its origin, and
   follow no redirects.
5. **Cache.** Key the cache on `(registry origin, team_id)`, reuse for at most
   60 s, and keep no expired fallback. A refresh failure returns
   `authority_unavailable`. A verified absent record returns
   `team_server_unpublished`. All three refusals fail closed, and the codes
   stay distinct so operators can tell an outage, a missing record and an
   unpublished rotation apart.

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

### The shipped pattern this extends

One credential type ships for apps: `Authorization: AWEB-App DIDKey …` with
`auth: "app-event"`. It is verified by `verify_app_event_auth`
(`server/src/aweb/app_events.py:29`–`:31`, `:82`–`:154`), and its key is
looked up in `app_registry_emit_keys` under the team's pinned digest
(`server/src/aweb/app_registry.py:462`–`:492`). The other credential types are
told apart the same way, by an exact `Authorization` prefix plus an exact
`auth` value (`identity-grant`, `server/src/aweb/identity_grant_auth.py:32`).
D1 names the `app-request` and `app-usage` purposes on that pattern but has
not built them.

### Proposed

One server verifier, `verify_app_credential(request, db, purpose)`, built
from the existing app-emit verifier and driven by a fixed purpose table:

| Purpose | `Authorization` prefix | `auth` | Key source |
| --- | --- | --- | --- |
| `app-event` | `AWEB-App DIDKey ` | `app-event` | a `team_app_emit_keys` row (acgh.8), or a `team_app_keys` row whose `purposes` contains `app-event` |
| `app-grant-read` | `AWEB-App-Grant-Read DIDKey ` | `app-grant-read` | `team_app_keys` row whose `purposes` contains it |
| `hook-resolve` | `AWEB-App-Hook-Resolve DIDKey ` | `hook-resolve` | `team_app_keys` row whose `purposes` contains it |

- **Headers and signed payload** are those of app-emit v1
  (`docs/app-events.md:105`–`:153`): `X-AWEB-App-ID`, `X-AWEB-App-Key-ID`,
  `X-AWEB-Team-ID`, `X-AWEB-Timestamp` and `X-AWEB-Signed-Payload`. The payload
  is canonical JSON of `{v: 1, auth, aud, method, path, team_id, app_id, kid,
  did_key, body_sha256, timestamp}`. Only `auth` and the prefix differ, so the
  checks are byte-for-byte the shipped checks: exact canonical form, 300 s
  skew, method, raw external path plus query, body hash, `aud` in the
  configured public origins.
- **Purpose binding is exact both ways.** The prefix selects the purpose, the
  signed `auth` must equal it, and the key must be registered for it. An
  `app-event` credential presented at a read endpoint is refused, and so is a
  read credential at `/v1/events/app`. The `app-event` row's bytes and the
  vector `app-emit-credential-v1.json` do not change.
- **The emit key stays emit-only by construction.** `event_emitters` rows live
  in their own table, and only the `app-event` purpose reads that table. A
  v2 `app_keys` entry may name the same physical `did_key` for several
  purposes, `app-event` among them (D1, "App keys are a generic,
  purpose-split set"), so a v2 app emits with an `app_keys` key. Each purpose
  is still verified separately, and the app-event wire bytes and
  `app-emit-credential-v1.json` do not change.
- **Reads do not bind installation id or generation.** The grant read is how
  the app *learns* them. D1's `app-request` and `app-usage` mutations do bind
  them, and keep their own verifiers.
- **Errors.** `401` for a malformed, mismatched or unsigned credential. `403
  app_key_not_registered` when no key is active for that purpose under the
  current installed digest. That code is also what an app sees once it has no
  installation.

### Key registration: keys come only from the pinned bytes

An app key is the app's own statement, so the server takes it only from the
manifest bytes that hash to the pinned digest. It never takes one from a
field the installer fills in. Otherwise any certified member could install an
app's real origin and digest with keys of its own. acgh.8 already makes every
registration a row of the installing team (`team_app_emit_keys`,
`team_app_event_types`), refuses a changed `did_key` for a registered key id,
keeps revocation one-way, and adds `manifest_registration()`, the reader of
declarations and keys from digest-pinned bytes. App keys follow the same rules.

- **Install carries the bytes.** The install request gains an additive,
  optional `manifest` field: the exact fetched bytes, base64, at most 10 MiB
  (`server/src/aweb/routes/apps.py:30`–`:40`). There is no `app_keys` request
  field.
- **The server checks the bytes** with `manifest_registration()`, extended to
  v2: `sha256(manifest)` must equal `digest`, the bytes must parse as the
  declared `manifest_version`, and `app.id` and `app.origin` must equal the
  request's. It then reads `app_keys: [{kid, did_key, purposes}]` (v2, frozen
  by C3) with a strict reader of only the fields it needs, held to C3's
  interpreter vectors. A mismatch refuses the install with a distinct error.
- **Rows are the installing team's.** A new ordered migration adds
  `team_app_keys (team_id, app_id, origin, digest, key_id, did_key, purposes
  TEXT[], created_at, revoked_at)`. As for emit keys, a key id keeps its first
  `did_key` within the team, a conflicting install gets `409`, and a revoked
  key stays revoked. The operator reseed of acgh.8 recreates these rows from
  the bytes as well.
- **Labels.** A purpose label is a lower-case token. An unrecognized label is
  stored and grants nothing, which is D1's rule.
- **What this does not prove.** Matching the digest does not prove that the
  origin serves those bytes. An installer can pin bytes of its own making, but
  only under its own digest and in its own team, where it already holds
  install authority (narrowed to admins by F6). Owner activation of a hook
  binding compares the digest the owner's client fetched from the origin
  (audit-substrate §A3), so bytes the installer made never activate. App
  events in that team, however, can be signed by keys those bytes declare,
  under the app's id. Event provenance (D1, aweb-acgh.1) should therefore show
  the install's digest and that the server did not verify it against the
  origin, so agents in that team do not read such events as the real app's.
  This is acceptable once install is admin-only (F6).
- **Transition.** While `manifest` is optional, an install that carries it is
  refused when separately supplied `event_emitters` or `events` differ from
  the bytes' declarations, or when `granted_scopes` is not a subset of the
  scopes the bytes' tools request. Requiring the bytes on every
  install is the end state (acgh.8 step 2), after it is measured that released
  clients send them, per the released-client rule.
- **No interim path.** v1 manifests declare no `app_keys` (strict v1 rejects
  unknown fields, `docs/app-manifest.md`, "Top-level structure"), so read
  purposes exist only for v2 installs after C3. Released clients send no
  `manifest`, so existing installs are unchanged.

### Per-team key revocation

A team's install authority, meaning F6's admin policy, may revoke one key for
its own team at once, without waiting for a new digest:
`POST /v1/apps/{app_id}/keys/{kid}/revoke`, with ordinary team auth. It sets
the team row's `revoked_at`, which is one-way, and enqueues the
post-mutation-hook event `app_key.revoked` (payload `app_id`, `kid`,
`purposes`; the envelope carries `team_id` and the actor) in the same
transaction, because which events a target
accepts is audit-relevant (audit-substrate §A6). The hooks catalog is a strict
allowlist, so this depends on `app_key.revoked` in audit-substrate §A10's v1
mutation types and in the hook-catalog and post-mutation-hook-sites vectors
(added at `98c1aa217`, §A10 and §A11) staying there through their freeze. Key rows are the team's own, so
one team can never disable an app for another. Revocation for every team is
the app's own act: it publishes new bytes, and each team installs the new
digest.

## 3. Grant status

```http
GET /v1/apps/self/grant
Authorization: AWEB-App-Grant-Read DIDKey <did:key> <sig>
```

The team and app come from the verified credential, never from a query
parameter, so an app can read only its own grant.

```json
{
  "team_id": "backend:acme.com",
  "app_id": "notes",
  "state": "active",
  "origin": "https://notes.example",
  "app_version": "1.4.0",
  "manifest_version": 1,
  "digest": "sha256:…",
  "granted_scopes": ["notes:read"],
  "installation_id": null,
  "generation": null,
  "as_of": "2026-10-19T12:00:00Z",
  "max_age_seconds": 60
}
```

- **`installation_id` and `generation`** are present from the start and `null`
  until F6 adds them, which is D1's rule. Consumers that bind them (task
  authorization, hook activation, the admission fence) refuse a `null` rather
  than synthesizing one from the digest or app id.
- **`state`** is `active` today. F6 adds `uninstalled` (for its lifecycle lane)
  without a version change. Every state other than `active` grants no normal
  use.
- **`max_age_seconds`** is configuration with a ceiling of 60 s. It is also the
  bound the hooks lane pads `active_from` with (audit-substrate §A3, §A4.4).

### Client semantics (the remote `GrantSource`)

| Server outcome | GrantSource result | B1 maps it to |
| --- | --- | --- |
| `200`, `state: active`, fresh | grant | scope check, then app policy |
| `200`, state other than `active` | not granted | `403 scope_denied` (no grant) |
| `403 app_key_not_registered` | not granted | `403` (no grant) |
| discovery unpublished | unavailable (`team_server_unpublished`) | `503 authority_unavailable` |
| timeout, `5xx`, TLS failure, cache past `max_age` with refresh failing | unavailable | `503 authority_unavailable` |

- A positive answer is reused for at most `min(max_age_seconds, 60)`, counted
  from the client's own receipt time. There is no stale fallback.
- An expired entry is never served, including while a refresh is in flight.
  Each refresh has a request timeout (configuration, default 5 s). A caller
  waiting on it receives unavailable when it fires, so the staleness bound is
  `max_age_seconds` itself, with no unbounded refresh on top.
- A definitive "not granted" may be cached for the same window.
- Concurrent misses for one `(team, app)` share one refresh.

### Revocation bound, stated honestly

A change on the server reaches every naapp within `max_age_seconds` plus the
time for one refresh:

- **Digest change (reinstall with new bytes).** Immediate on the server: keys
  are digest-scoped, so the old digest's read keys stop verifying, and the
  grant answer shows the new digest and scopes.
- **Uninstall and generation change (F6).** The answer flips state, or its
  generation, on the next read. A short cache is not an admission fence, so
  F6's fence remains the guarantee against admitting work under an obsolete
  generation. This API gives the bounded-staleness half.

## 4. Hook resolution

Shaped with the aw-hooks seat (audit-substrate §A4). Both reads use the
`hook-resolve` credential:

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
  bindings of both kinds, so a target can confirm that the `binding_id` a
  delivery names is its own active registration (audit-substrate §B2, step 2).
- **Response.** Each binding carries `binding_id`, `kind`, `app_id`,
  `installation_id`, `generation`, `origin`, the resolved `method` and raw
  `path`, `digest`, and `active_from`. Productions also carry the producer's
  active keys of that generation whose declared purposes include
  `hook-event` or `hook-delivery`, each as `{kid, did_key, purposes}`; an
  emit-only or usage key is never listed. The response envelope carries
  `as_of` and `max_age_seconds` (≤ 60).
- **Historical verification.** Responses list currently active keys only.
  Verifying an event after its producer's key was retired relies on the key
  evidence the target records at ingest (logs' ingest record, audit-substrate
  §B2). This API keeps no key history for apps.
- **A refused read** returns `403 hook_binding_required`. An unknown catalog
  id, version or hook resolves to nothing, and is reported as `200` with an
  empty list only when the caller holds the complementary binding. That
  binding cannot exist for an unknown hook, so in practice the answer is
  `403`.
- **Client-class hooks.** A member authenticated by ordinary team-auth v2 may
  list registrations for client-class hooks only, through the same path with
  the member envelope. This is how `aw` finds `post-command-hook` targets.
- **The core producer's keys.** `GET /v1/hooks/producer-keys`, anonymous on
  the discovered server URL, returns `{keys: [{kid, did_key, valid_from,
  valid_until|null}]}`, retired keys included. These are operator
  configuration, never a team, controller or agent key. A consumer anchors the
  core origin per team through the §1 chain, at install or first resolution,
  and caches it under §1's rules. It never takes an origin from an event or a
  request. When the team's `aweb.team-server/1` record changes, the consumer
  re-resolves; events received before the change keep verifying from the key
  evidence recorded at their ingest.
- **Client.** The client keeps a cache of at most 60 s and fails closed on
  expiry plus refresh failure, as grant status does.
- **Dependency.** Bindings are child rows of the installation (the hooks
  lane's `app_hook_bindings`, keyed by F6's `installation_id`). This lane
  builds these endpoints and the client once that table exists. It does not
  define binding state or activation.

## 5. Client in `aweb_naapp.runtime`

Placed under B1's `runtime` extra, which already depends on `awid-service`
and `httpx` (`naapp-lib/pyproject.toml` on `agents/aweb-protocol-expert-naapp-verifier`):

- `TeamServerDirectory`: `resolve(team_id) -> TeamServer(server_url, audience, team_did_key)`, implementing the §1 chain. It reuses the same registry selection and team-key cache as B1's verifier rather than a second copy.
- `AppCredentialSigner(app_id, kid, key, purpose)`: signs one purpose, with
  a key from the lane's single app-key loader:
  - **Configuration names keys by kid**: a map from kid to key file. Which
    purposes a kid may sign comes from the pinned manifest's `app_keys`, not
    from configuration, so the signer for a purpose picks the configured kid
    the manifest declares for it and refuses at startup when there is none.
  - **One loader**, in a dependency-light `aweb_naapp` module (standard
    library and `pynacl` only) so that core can load its own hook-producer key
    with it too, runs once at startup and fails startup on a missing,
    unreadable or malformed key. No naapp parses key bytes
    itself.
  - **File checks**: a regular file, not group- or world-writable. Read bits
    are left to the platform, because standard mounted secrets (Kubernetes
    0644, Docker 0444, platform secret files) are world-readable inside a
    single-user container.
  - **One format**: 64 lowercase or uppercase hex characters (the Ed25519
    seed), with one trailing newline allowed.
  - **Never logged**: key material appears in no log, error, repr or
    settings dump, and a test proves it.
  - **Released value form**: the per-app `*_APP_EMIT_KEY_SEED_HEX` setting
    stays accepted for the `app-event` key only, read by the same loader,
    until it is measured that no deployment uses it (open question 5).
- `TeamGrantSource`: the remote implementation of B1's `GrantSource`
  (`aweb_naapp.runtime.authorization`), using
  `async grant_for(team_id) -> Grant | None`:
  - an active installation of this app returns
    `Grant(team_id, scopes, fresh_until, installation_id, generation)`, where
    `fresh_until` is the client's monotonic receipt time plus
    `min(max_age_seconds, 60)`;
  - an inactive state or `app_key_not_registered` returns `None`, which B1
    maps to `403`;
  - unpublished discovery, an outage, a timeout or a malformed answer raises
    `GrantUnavailable`, which B1 maps to `503 authority_unavailable`.

  The source itself checks the answer's `app_id`, `origin` and `digest`
  against the app's own identity before returning a grant.
- `HookResolver`: `registrations(team_id, catalog, version, hook)` and `productions(…)`, with the §4 semantics.

## 6. Proposed build split

| Step | Contents | Depends on |
| --- | --- | --- |
| G1-a | AWID `aweb.team-server/1`: migration, PUT/GET routes, `aw id team set-server/show-server`, conformance vector `team-server-record-v1.json` | **Juan's identity-path approval** |
| G1-a′ | Custodial deployment publishes and backfills records for the teams whose controller key it holds (hosted operator's build) | G1-a |
| G1-b | Server: generalized purpose verifier (app-event unchanged and vector-checked), `team_app_keys` migration, install `manifest` bytes through `manifest_registration()`, per-team key revocation, `GET /v1/apps/self/grant`, vector `app-read-credential-v1.json` | design ACK, acgh.8 landed, C3 `app_keys` shape |
| G1-c | `aweb_naapp.runtime`: directory, signer, `TeamGrantSource` | G1-a, G1-b, B1 `GrantSource` |
| G1-d | Hook resolution endpoints including own bindings, producer keys, `HookResolver` | hooks-lane binding table, F6 |

Each step is TDD with tests in both directions. Server tests run on real
Postgres through the existing pgdbm fixtures (`server/tests/conftest.py`).
AWID tests run against a real AWID service. Signatures come from the
conformance vectors, not mocks. The real-stack check extends the existing
Docker e2e harness, with AWID, aweb and one fixture naapp.

## Open questions for Juan

1. **Approve the `aweb.team-server/1` identity-path change** (§1): an AWID
   schema and route, signed by the team key. It needs your explicit approval
   and Athena's review. *Recommendation: approve.* It is the only option where
   the controller authorizes the binding and a newer record supersedes an
   older one.
2. **Existing teams of custodial deployments.** Teams created before the
   record existed need a one-time publication by the deployment that holds
   their controller key. Until that runs, they fail closed at naapps.
   *Recommendation: the custodial deployment backfills records for its
   existing teams before any naapp depends on discovery. No interim pin.*
3. **Ownership of installation identity.** F6 owns `installation_id`,
   generation, state and uninstall. This lane reads them and reports `null`
   until then. *Recommendation: keep that split rather than adding columns
   here*, so one lane owns the install schema.
4. **Disclosure of a private team's server URL** (§1, Privacy), for you and
   for Athena's review (her G5). Anyone who
   knows a private team's id can read its coordination server URL; certificate
   status discloses only the team key. *Recommendation: accept.* A server URL
   is not a credential, every request to it is still authenticated, and the
   alternative, an authenticated read, would leave a naapp unable to discover
   a team before it can authenticate to it.
5. **One rule for loading app keys** (§5), agreed with the shared naapp
   runtime seat. Released Folio and Library load their emit seed as a
   configuration value. *Recommendation: one loader for every app key and
   purpose, reading key files named by kid; the released seed-value setting
   stays accepted for the `app-event` key only until it is measured that no
   deployment uses it, and is never extended to new purposes.* If a platform
   that can only supply environment values appears, extending the value form
   would be your decision.
