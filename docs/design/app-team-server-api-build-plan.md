# App → team-server API: build plan

Status: **task-level build plan for aweb-acgh.7** (build epic aweb-acgh.17),
with each task's status against main. The design is
[`app-team-server-api.md`](app-team-server-api.md), accepted under Juan's
delegation (decisions 3, 9 and 10). Each task carries its board id and one
status: **Built** (on main, with the code and commit that hold it), **In
flight** (partly on main; the entry says which part), **Open** (decided and
planned, not on main) or **After the first release** (decided, deliberately
parked). Built tasks are summarized; open tasks keep their scope and
acceptance. Every task is built test-first on its own branch and lands only
after an exact-SHA ACK from a non-author reviewer.

## Status at a glance

| Plan task | Board task | Status |
| --- | --- | --- |
| acgh.8 step 1: team-scoped emit keys | aweb-acgh.8 | **In flight**: team-scoped keys and key derivation from origin-fetched bytes are on main; team and operator revocation are not (G1-b3, G1-b3e) |
| G1-a1: AWID record, routes and vector | aweb-acgh.17.1 | **Built** |
| G1-a2: `aw` publish, show and rotation coupling | aweb-acgh.17.2 | **Built** |
| G1-a3 (hosted): custodial publication and backfill | aweb-acgg.31 | hosted build; OSS support **Built** |
| G1-b1: generalized app credential verifier | aweb-acgh.17.3 | **Built** |
| G1-b2a: keys from verified manifest bytes | aweb-acgh.17.4 | **Built**, with install fetching the bytes from the origin |
| G1-b2b: v2 `app_keys` from bytes | aweb-acgh.17.5 | **Built** |
| G1-b3: key revocation (team and operator) | aweb-acgh.17.6 | **Open** |
| G1-b3e: `app_key.revoked` in the revoke transaction | aweb-acgh.17.7 | **Open** |
| G1-b4: grant status read | aweb-acgh.17.8 | **Built** |
| G1-c1: one app-key loader | aweb-acgh.6 | **Built** |
| G1-c2: team-server discovery client | aweb-acgh.17.9 | **Built** |
| G1-c3: signer and `TeamGrantSource` | aweb-acgh.17.10 | **Built** |
| G1-d1: server resolution endpoints | aweb-acgh.17.11 | **Built**, except the member path (G1-d1b) |
| G1-d1b: client-class registrations for a member | aweb-acgh.17.18 | **Open** |
| G1-d2: `HookResolver` client | aweb-acgh.17.12 | **Built** |
| G1-e1: discovery and grant, end to end | aweb-acgh.17.13 | **Open** |
| G1-e2: hook resolution, end to end | aweb-acgh.17.14 | **Open** |
| Install-bytes column 028 | aweb-acgh.17.17 | **Open** (the column decision only) |
| Serialized key identity registration | aweb-acgh.17.19 | **Open** |
| Idempotent app-event ingest | aweb-acgh.9 | **Open** |
| Global request-body cap | aweb-acgh.20 | **Built** |

## Ground rules for every task

- **TDD, both directions.** Each behaviour change has a test that was seen
  failing, and a valid neighbouring case that still passes.
- **Real paths.** Server tests use real Postgres through the existing pgdbm
  fixtures (`server/tests/conftest.py`). AWID tests run against a real AWID
  service. Signatures come from conformance vectors or real keys generated in
  the test, never from mocks of the verifier.
- **Credentials by name only.** Test keys are generated in the test or are
  the existing disposable e2e seeds named in compose files (for example
  `FOLIO_APP_EMIT_KEY_SEED_HEX` in `scripts/e2e/folio-wakes.compose.yml`). No
  secret value appears in a task, a mail, a log or evidence.
- **Schema.** Every schema change is a new ordered migration, numbered after
  whatever main holds when the task lands.
- **Docs in the same change.** Each task updates the source-of-truth document
  its contract lives in (`docs/awid-sot.md`, `docs/app-registry.md`,
  `docs/app-events.md`, the aw command reference) and passes
  `scripts/check_sot_source_inventories.py` and `scripts/check-extension-docs.py`.
- **Vectors.** A task that adds a conformance vector or a consumer of one
  registers both and passes `make test-vector-provenance`
  (`scripts/check_vector_provenance.py`).
- **Released clients.** Changes are additive. A narrowing names its consumers
  and waits for measurement (cross-repo-change skill). Naapps keep no
  backward compatibility for released `aw` clients (decision 44).
- **Heavy runs** go through the suite lock.

All tasks need the aweb-protocol-expert soul unless marked otherwise, on
Claude Opus 5.5.

## Order of the open work

Generic pieces live in `aweb_naapp` (naapp-lib, `runtime` extra); core holds
only generic install authority and verification. No task adds an app name to
shared or core code.

| Task | Can start when |
| --- | --- |
| G1-b3 (aweb-acgh.17.6) | its dependencies, acgh.8 step 1 and F6's admin policy, are on main |
| G1-b3e (aweb-acgh.17.7) | G1-b3, and the core post-mutation-hook outbox, S2 (aweb-acgh.16.11) |
| G1-d1b (aweb-acgh.17.18) | its dependency is on main; it must land before anything fires `post-command-hook` |
| G1-e1 (aweb-acgh.17.13) | steps 1-3, 5 and 6 depend only on main; step 4's revoke needs G1-b3 |
| G1-e2 (aweb-acgh.17.14) | the hooks lane's delivery path (S2, aweb-acgh.16.11) |
| aweb-acgh.17.17, aweb-acgh.17.19, aweb-acgh.9 | no dependency |

## A. Discovery: `aweb.team-server/1`

### G1-a1: AWID record, routes and vector (aweb-acgh.17.1)

**Built** (f6f0c5f9c, with the `issued_at` fix ddfb0486d, aweb-acgh.17.15).
`awid/src/awid_service/migrations/008_team_server_records.sql`;
`publish_team_server` and `get_team_server` in
`awid/src/awid_service/routes/teams.py`; `awid/src/awid/team_server_record.py`;
vector `docs/vectors/team-server-record-v1.json`, registered in
`scripts/check_vector_provenance.py`; contract in `docs/awid-sot.md`.

What main enforces, beyond the design's record rules: `server_url` is
canonical, at most 2048 bytes, `http` only for loopback, and no literal
non-loopback IP; the signature has one accepted encoding; the body is
bounded at 8 KiB; publishing is rate-limited with a trusted-publisher
exemption. A record that does not verify (a wrong or stale key, another
team, a bad signature, a malformed record) gets the same `404` as an unknown
team, so a publish never reveals that a private team exists; a non-newer
record gets `409 not_newer`, and other refusals `422`.

### G1-a2: `aw` publish, show and rotation coupling (aweb-acgh.17.2)

**Built** (2758419b2, landed in f6f0c5f9c). `aw id team set-server` and
`aw id team show-server` (`cli/go/cmd/aw/id_team_server.go`,
`cli/go/awid/team_server.go`), with the conformance consumer
`cli/go/internal/conformance/team_server_record_test.go`.

Rotation coupling: `aw id team rotate-key` (ecc038d7b, aweb-acgh.18.24) sends
the team-server record re-signed with the new key in `resigned_records`, and
AWID replaces it in the rotation's own transaction (decision 26;
`awid/src/awid_service/attestation_rotation.py`). There is no window in which
the new key sits next to an old-key record. `aw` never infers a coordination
server from the canonical registry for this record.

### G1-a3 (hosted): custodial publication and backfill (aweb-acgg.31)

Hosted-side item H1, on the board as L6 (aweb-acgg.31); its build is in the
hosted repository. The OSS support it uses is **Built**: the public Python
publishing and signing API (b11720875, `awid/src/awid/registry.py`,
`awid/src/awid/team_server_record.py`) and the trusted-publisher rate-limit
exemption (667486858).

## B. Server: purpose-split app credentials and grant status

### acgh.8 step 1: team-scoped emit keys (aweb-acgh.8)

**In flight.** On main: emit keys and event types are rows of the installing
team (`team_app_emit_keys`, `team_app_event_types`, migrations 024-026), and
keys come only from the manifest bytes the server fetches from the origin
(G1-b2a). Not on main: team and operator key revocation, G1-b3 and G1-b3e.

### G1-b1: generalized app credential verifier (aweb-acgh.17.3)

**Built** (10707b85c). `verify_app_credential(request, db, purpose)` with a
fixed purpose table in `server/src/aweb/app_credentials.py`;
`verify_app_event_auth` is a wrapper over it. `app-emit-credential-v1.json`
verifies unchanged, and each purpose refuses the others' credentials. The
`team_app_keys` migration (027) landed here, an approved plan deviation. The
table also carries `app-request`, which binds `installation_id` and
`installation_generation` to an active, origin-verified installation
(b3e7b00b2). The read purposes and `app-request` accept only the strict
signature encoding (Athena's ruling, recorded on aweb-acgh.17.5); `app-event`
keeps its released lenient decoder.

### G1-b2a: keys from verified manifest bytes (aweb-acgh.17.4)

**Built.** The install request carries no manifest bytes: it is `app_id`,
`origin`, `digest`, `granted_scopes` and `expected_generation`, with unknown
fields refused (`AppInstallRequest`, `server/src/aweb/routes/apps.py`). The
server fetches the exact bytes from the declared origin through shared
egress, requires them to hash to `digest`, derives emit keys, event types
and app keys from them, and stores them on the installation (85089aca4;
`manifest_bytes`, migration 035). Installer-uploaded bytes are not
installation authority (`docs/app-registry.md`). Install, update and
uninstall require the current install admin and write the operator audit row
in the same transaction. An installation becomes `active` only with
`origin_verified` and stored bytes, so naapps keep no path for released
clients that sent no bytes (decision 44).

### G1-b2b: v2 `app_keys` from bytes (aweb-acgh.17.5)

**Built** (72a3fc5c7, with the shared identity repair ec0977f04).
`team_app_keys` rows come from v2 `app_keys` read by the one manifest reader,
`aweb_naapp.manifest.load_manifest` (decision 56), in
`server/src/aweb/app_registry.py`. A key id keeps its first `did_key`, a
conflict gets `409`, revocation is one-way across digests and manifest
versions, and unknown purpose labels are stored and grant nothing.
`aweb reseed-app-registrations` (`server/src/aweb/cli.py`) recreates the rows
from bytes and reports `key_conflict` teams.

### G1-b3: key revocation, team and operator (aweb-acgh.17.6)

**Open.**

- **Repo/paths:** `server/src/aweb/routes/apps.py`, `server/src/aweb/cli.py`.
- **Contents:**
  - `POST /v1/apps/{app_id}/keys/{kid}/revoke` sets the team row's one-way
    `revoked_at` under the team's install authority (F6 admin policy,
    `require_install_admin`), for emit keys and app keys alike.
  - The post-mutation-hook event `app_key.revoked` (payload `app_id`, `kid`,
    `purposes`; `team_id` and the actor in the envelope, audit-substrate
    §A10) is added by G1-b3e below.
  - An operator command, `aweb revoke-app-key --team <id> --app <id> --kid
    <kid>`, does the same for a named key: the remedy for a reseed
    `key_conflict`.
- **Acceptance:**
  - revocation takes effect on the next credential check;
  - a member without install authority is refused;
  - one team's revoke never touches another team's rows;
  - the operator audit row is written in the revoke transaction or not at all;
  - nothing reactivates a revoked key.
- **Audit:** the team route and the operator command both write the
  append-only operator audit row in the same transaction as `revoked_at`.
  That row is required from the first landing, so a revocation never exists
  without an audit record and this task does not wait on the hooks outbox.
- **Depends on:** nothing that is not on main.
- **Review:** reviewer plus Athena.

### G1-b3e: `app_key.revoked` in the revoke transaction (aweb-acgh.17.7)

**Open.** Once the core post-mutation-hook outbox (S2, aweb-acgh.16.11) is on
main, the revoke also enqueues `app_key.revoked` in the same transaction,
with a test that the event and `revoked_at` commit together or not at all.
The catalog carries the type (`docs/hook-events.md`).
Depends on G1-b3 and S2. Review: reviewer plus Athena.

### G1-b4: grant status read (aweb-acgh.17.8)

**Built** (848f9e85a, e4f8bf840, 214f340c3). `GET /v1/apps/self/grant`
(`app_grant_status_route`, `server/src/aweb/routes/apps.py`), vector
`test-vectors/app-read-credential-v1.json` (purposes `app-grant-read` and
`hook-resolve`, with cross-purpose and encoding negatives). The answer
always carries `installation_id` and `generation`, a state among
`pending_origin_verification`, `active` and `uninstalled`, `origin_verified`
and `installed_at`, with `as_of` and `max_age_seconds` (configured, ceiling
60). Grant-read keys stay valid in every installation state, so an
uninstalled app reads `200` with `state: uninstalled`; `403
app_key_not_registered` means the installation is gone or pinned to another
digest.

## C. `aweb_naapp.runtime` clients

### G1-c1: one app-key loader (aweb-acgh.6)

**Built** (14338a55b, 2e0fa96c2). `aweb_naapp.signing_key` behind the
`signing-key` extra (`pynacl` only), with the file checks in
`aweb_naapp.key_file.read_key_file` (regular file, not group- or
world-writable), and `load_app_key` in `runtime/app_keys.py`, which takes
the purposes a kid may sign from the manifest. One 64-hex format; key
material never logged; the released `*_APP_EMIT_KEY_SEED_HEX` value accepted
for the `app-event` key only (decision 10).

### G1-c2: team-server discovery client (aweb-acgh.17.9)

**Built** (eea90889d, c1b9062cc). `TeamServerDirectory`
(`naapp-lib/src/aweb_naapp/runtime/team_server.py`): the verifier's
configured registry, the shared `AWIDTeamCache`, no redirects, a cache of at
most 60 s keyed on (registry origin, team id) with no expired fallback. Six
distinct refusals: `team_server_unpublished`, `team_unknown`,
`team_server_key_mismatch`, `team_server_record_invalid`,
`registry_mismatch` and `authority_unavailable`.

### G1-c3: app credential signer and `TeamGrantSource` (aweb-acgh.17.10)

**Built** (d052a7845, b93cc7dff, 1945aee3f; the shared runtime directory per
decision 69 in e6b14c292). `AppCredentialSigner(*, app_id, key, purpose)` in
`runtime/app_credentials.py`; `TeamGrantSource` in `runtime/team_grants.py`,
with `grant_for` (B1's `GrantSource`) and `status_for` (typed `GrantStatus`,
inactive and unknown states preserved, decision 48b), sharing one bounded,
coalesced read. A missing-key denial is cached for at most five seconds.
Transport failures raise `GrantUnavailable` with `grant_refresh_timeout`,
`grant_server_unreachable` or `grant_answer_malformed`.

## D. Hook resolution

### G1-d1: server resolution endpoints (aweb-acgh.17.11)

**Built**, except the member path, which is G1-d1b (330212e0d, f562e8d33,
2533d68d3, c615b2224, f4d34e189, reconciled in 39dcb07be).
`server/src/aweb/routes/app_hooks.py`: registrations and productions under
`hook-resolve`, each authorized by the complementary active binding;
productions list hook-purpose keys only; own bindings by `binding_id` or by
`hook` (exactly one, else `400`), in every state; anonymous
`GET /v1/hooks/producer-keys` with validity windows. Every response carries
`as_of` and `max_age_seconds`.

### G1-d1b: client-class registrations for a member (aweb-acgh.17.18)

**Open.**

- **Contents:** the team-auth v2 member path on
  `GET /v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/registrations`
  (design §4, "Client-class hooks"). A member may list registrations for
  client-class hooks only; this is how `aw` finds `post-command-hook`
  targets. The credential type decides which rule applies: a member envelope
  never reaches productions, own bindings or a server-class hook. The hook's
  class comes from the one catalog reader, `aweb_naapp.hooks.catalog`.
- **On main:** every resolution route refuses a member envelope with the same
  `401` as any credential that is not `hook-resolve`, never an empty `200`.
- **Acceptance:**
  - a member lists the active client-class registrations of the hook in
    their own team;
  - a member asking about a server-class hook, or for productions or own
    bindings, is refused;
  - a member of another team sees nothing of this team;
  - a revoked certificate is refused;
  - each rule is tested in both directions on real Postgres.
- **Depends on:** the server taking `aweb-naapp[hooks]`, which it does
  (`server/pyproject.toml`). Must land before anything fires
  `post-command-hook`.
- **Review:** reviewer plus Athena.

### G1-d2: `HookResolver` client (aweb-acgh.17.12)

**Built** (b9626d38b, 8ad5875f7, 7373fd46b, a4e108372, 30af2173b).
`naapp-lib/src/aweb_naapp/runtime/hook_resolver.py`: `registrations`,
`productions`, `own_bindings` and `core_producer_keys`, with the core origin
anchored per team through `TeamServerDirectory`, re-resolution when the
team-server record changes, and a cache of at most 60 s that fails closed.
The runtime builds one and shares it (`NaappRuntime.hook_resolver`, decision
69).

## E. Real-stack acceptance

### G1-e1: discovery and grant, end to end (aweb-acgh.17.13)

**Open.** Partial coverage on main: `scripts/e2e/folio_wakes.py` publishes a
record with `aw id team set-server`, and `scripts/e2e/folio_uninstall_grant.py`
reads `/v1/apps/self/grant`.

- **Repo/paths:** a new script under `scripts/e2e/`, reusing the folio-wakes
  compose stack (AWID, aweb, Folio) plus one generic fixture naapp built on
  `aweb_naapp.runtime`.
- **Scenario:** no mocks, with disposable identities.
  1. A BYOT team publishes its server record with `aw id team set-server`.
  2. The fixture naapp discovers the server and reads its grant.
  3. A member call passes B1 with that grant.
  4. A digest change, then a per-team key revoke, take effect within
     `max_age`.
  5. An unpublished team gets `503`, and a rotated team key without the
     re-signed record gets `503 team_server_key_mismatch`.
  6. Stopping AWID or aweb gives `503` after the cache bound, never a stale
     grant.
- **Done-signal:** green run with evidence, harness shown failing against a
  deliberately broken build.
- **Depends on:** G1-b3 for step 4's revoke; the rest is on main.
- **Review:** reviewer.

### G1-e2: hook resolution, end to end (aweb-acgh.17.14)

**Open.**

- **Scenario:**
  1. A producer fixture resolves an owner-activated registration and delivers
     to it.
  2. The target confirms its own binding and the producer's hook-purpose key.
  3. Revoking the binding stops delivery within `max_age`.
- **Depends on:** the hooks lane's delivery path (S2, aweb-acgh.16.11).
- **Review:** reviewer.

## F. Follow-ups

### Install-bytes column 028 (aweb-acgh.17.17)

**Open**, for one decision only. Install refuses to activate without
origin-fetched bytes (G1-b2a), so "install requires manifest bytes" holds on
main with no measurement step (decision 44). What remains is whether
migration 028's `registered_from_manifest_bytes` column stays: verified
installs set it, and `server/src/aweb/hook_bindings.py` reads it. Any removal
is a new ordered migration. Review: reviewer plus Athena.

### Serialized key identity registration (aweb-acgh.17.19)

**Open.** Two concurrent registrations of the same team, app and kid with
different `did_key`s can both pass the identity check. Authentication stays
fail-closed, because both lookups reject differing historical identities, so
the outcome is an unusable key registration. Contents: per-(team, app, kid)
serialization in the shared registration writer, preserving lock order and
install rollback. Acceptance: a real concurrent PostgreSQL test that tells
the refused conflicting registration from a valid same-identity one.

### Idempotent app-event ingest (aweb-acgh.9)

**Open.** `POST /v1/events/app` mints its own `event_id`, so a retried emit
stores a second event (`docs/app-events.md`). Contents: core accepts an
optional emitter-supplied `event_id` and deduplicates on
`(team_id, app_id, event_id)`: an identical body gives `200` with the
original event, a different body `409`. Additive. Acceptance: real-server
tests for both cases; the aw and channel consumers unchanged;
`docs/app-events.md` updated. Review: reviewer plus Athena.

### Global request-body cap (aweb-acgh.20)

**Built** (8e4ac51ae). `RequestBodyCacheMiddleware` in
`server/src/aweb/api.py` refuses a body with `413` as soon as it is declared
or read past the cap, before buffering it; the cap is
`AWEB_MAX_REQUEST_BODY_BYTES`, default 16 MiB. Routes with tighter bounds
keep theirs.

## Hosted-side items

The OSS contract states each of these as a generic requirement on a custodial
deployment. They map onto existing hosted board tasks, whose build lives in
the hosted repository.

| Item | Requirement | Board task | Depends on |
| --- | --- | --- | --- |
| H1 | Publish an `aweb.team-server/1` record for every team whose controller key the deployment holds: at creation and on any move. A team-key rotation carries the re-signed record in `resigned_records` (decision 26, HO2). Backfill all existing teams before any naapp depends on discovery. No interim pin or default (decision 3). | L6, aweb-acgg.31 | G1-a1 (built) |
| H2 | The hosted install path goes through the server's install, which fetches the bytes from the origin. It sends no manifest bytes, keys or event declarations, and reads no `app_registry_emit_keys` or `app_registry_event_types` rows. | L1, aweb-acgg.21 | G1-b2a (built) |
| H3 | Hosted admin controls for per-team key revocation call the G1-b3 route under the hosted admin policy. | L1, aweb-acgg.21 | G1-b3 (**Open**, aweb-acgh.17.6) |
| H4 | Deploy steps for each server release that migrates registrations, run during that release's production deploy: reseed right after migrating (`aweb reseed-app-registrations`) and report `key_conflict` teams. | operations deploy, not a build task | each such release |

## Cross-lane dependencies

| Dependency | Needed by | On main |
| --- | --- | --- |
| aweb-acgh.8 step 1, team-scoped registrations | G1-b1, G1-b2a, G1-b3 | yes |
| aweb-acgh.1 hook contract (catalog with `app_key.revoked`, envelope, binding vectors) | G1-b3e, G1-d1 | yes |
| Core post-mutation-hook outbox, S2 (aweb-acgh.16.11) | G1-b3e, G1-e2 | no |
| aweb-acgh.1 `app_hook_bindings` and owner activation (migration 032) | G1-d1 | yes |
| aweb-acgh.6 runtime extraction (outbox emit) | G1-c1 | yes |
| aweb-acgh.4 approvals and passkeys | none here | — |
| D1 C3 (aweb-acgg.9) manifest v2 `app_keys` shape and interpreter vectors | G1-b2b | yes |
| D1 F6 (aweb-acgg.5) installation identity, admin policy, uninstall (migration 035, `install_admins.py`) | G1-b3 (route authority), G1-b4 (fields), G1-d1 | yes |
| D1 L6 (aweb-acgg.31) custodial record publication and backfill | G1-e1 for hosted teams; any naapp depending on discovery for a hosted team | hosted |
| D1 L1 (aweb-acgg.21), L2 (aweb-abzo), L3 (aweb-acgg.22) | consume G1-c3 and G1-d2; nothing here waits on them | hosted / consumers |
