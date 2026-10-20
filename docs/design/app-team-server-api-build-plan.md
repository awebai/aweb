# App → team-server API: build plan

Status: **task-level build plan for aweb-acgh.7**, for review by the
independent reviewer and Athena. The design is
[`app-team-server-api.md`](app-team-server-api.md) at `2ee4615a9`, accepted
under Juan's delegation (decision record of 2026-10-19, items 3, 9 and 10).
This is a plan, not code: every task below is built test-first on its own
branch and lands only after an exact-SHA ACK from a non-author reviewer.

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
  and waits for measurement (cross-repo-change skill).
- **Heavy runs** go through the suite lock.

All tasks need the aweb-protocol-expert soul unless marked otherwise, on
Claude Opus 5.5.

## Order of work

The hook contract (aweb-acgh.1's catalog, envelope and binding vectors) lands
first in its own lane. This plan's discovery and credential work does not
wait for it. Only hook resolution (G1-d) does.

| Wave | Tasks | Can start when |
| --- | --- | --- |
| 0 | acgh.8 step 1 lands and ships | its whole-suite and real-stack runs are green |
| 1 | G1-a1, G1-b1, G1-b2a, G1-c1 | now (G1-b1 and G1-b2a after acgh.8 lands) |
| 2 | G1-a2, G1-c2, G1-b2b, G1-b3 | their dependencies below |
| 3 | G1-b4, G1-c3, G1-e1 | waves 1 and 2 |
| 4 | G1-d1, G1-d2, G1-e2 | the hooks binding table and F6 |

Generic pieces live in `aweb_naapp` (naapp-lib, `runtime` extra); core holds
only generic install authority and verification. No task adds an app name to
shared or core code.

## A. Discovery: `aweb.team-server/1`

### G1-a1: AWID record, routes and vector

- **Repo/paths:** `awid/src/awid_service/` (new migration, routes),
  `docs/awid-sot.md`, `test-vectors/team-server-record-v1.json`.
- **Contents:**
  - `PUT /v1/namespaces/{domain}/teams/{name}/server` stores
    `{record, signature}` after verifying the signature against the team's
    current key over `"aweb.team-server/1\n" || canonical_json(record)`.
  - The record must be newer than the stored one, and its `issued_at` no more
    than five minutes ahead of AWID's clock.
  - `server_url` is validated as https, or localhost http in development.
  - `GET` on the same path is anonymous for public and private teams. It
    returns the stored bytes, with an identical `404` for an unknown team and
    for a team with no record.
- **Vector:** positive cases plus negatives for:
  - the wrong domain prefix;
  - a non-current team key;
  - a team mismatch;
  - a far-future `issued_at`;
  - a non-newer `issued_at`;
  - an http `server_url` outside localhost.
- **Acceptance:** every vector case is verified by the AWID tests. A
  rotation through `POST /v1/namespaces/{domain}/teams/{name}/rotate` leaves
  the stored record refused by its consumers until it is re-signed. Juan's
  approval (delegated decision 3) is cited in the commit.
- **Done-signal:** SHA ACKed by the reviewer and Athena, landed on main.
- **Depends on:** nothing.
- **Review:** reviewer plus Athena (identity path).

### G1-a2: `aw` publish, show and rotation coupling

- **Repo/paths:** `cli/go/cmd/aw/`, `cli/go/awid/`, the CLI reference doc,
  and the conformance consumer of `team-server-record-v1.json`.
- **Contents:**
  - `aw id team set-server --url <server_url>` signs under the existing
    controller custody (BYOT or local) and publishes.
  - `aw id team show-server` reads the record and verifies it.
  - Any `aw` path that rotates a team key re-signs and publishes the record in
    the same operation. A failed publish is reported, and retrying it is
    idempotent. `aw` has no team-rotate command today; when one is added it
    carries this rule.
  - `aw` never infers a coordination server from the canonical registry for
    this record. The `init.go` hosted fallback is untouched by this task.
- **Acceptance:**
  - the Go signer is byte-identical to the vector;
  - a real-AWID test publishes, reads and verifies a record;
  - a refused publish (stale key, future time) surfaces AWID's distinct
    error.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-a1.
- **Review:** reviewer plus Athena.

### G1-a3 (hosted): custodial publication and backfill

Hosted-side item H1, on the board as L6 (aweb-acgg.31).

## B. Server: purpose-split app credentials and grant status

### G1-b1: generalized app credential verifier

- **Repo/paths:** `server/src/aweb/app_events.py` → shared verifier module,
  `server/tests/`.
- **Contents:** `verify_app_credential(request, db, purpose)` takes a fixed
  purpose table:
  - each purpose has its own `Authorization` prefix and its own exact `auth`
    value;
  - each purpose names its key source;
  - every check is the app-emit v1 check.
  The `app-event` purpose keeps today's bytes and reads `team_app_emit_keys`
  (acgh.8).
- **Acceptance:**
  - `app-emit-credential-v1.json` still verifies unchanged;
  - a credential signed for one purpose is refused at another purpose's
    endpoint, in both directions;
  - a wrong prefix with a right `auth` is refused, and so is the reverse.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** acgh.8 landed.
- **Review:** reviewer plus Athena.

### G1-b2a: install carries v1 manifest bytes (acgh.8 step 2)

- **Repo/paths:** `server/src/aweb/routes/apps.py`, `server/src/aweb/app_registry.py`
  (`manifest_registration()`), and `cli/go/cmd/aw/app_events.go` together with
  `plugin.go`, as a cross-repo change in one repository.
- **Contents:**
  - The install request gains an optional `manifest` field: base64 of the
    exact bytes, at most 10 MiB.
  - When present, the server derives `event_emitters` and `events` from the
    bytes. It refuses an install whose separately supplied fields differ, or
    whose `granted_scopes` are not a subset of the scopes the bytes' tools
    request.
  - `aw plugin install/update` sends the exact fetched bytes.
  - The server records whether each install carried bytes, so the later
    "require bytes" narrowing can be measured.
  - Install and update write the append-only operator audit row
    (`record_coordination_audit`) in the same transaction as their key
    registration.
- **Acceptance:**
  - a member cannot register an emit key or declaration that the pinned bytes
    do not declare, when bytes are carried;
  - released clients without bytes behave exactly as after acgh.8;
  - the measurement is queryable by an operator.
- **Done-signal:** SHA ACKed, landed, and released with the next aw and
  server release.
- **Depends on:** acgh.8 landed.
- **Review:** reviewer plus Athena.
- **Follow-up, not in this plan:** require bytes once measurement shows
  released clients send them.

### G1-b2b: v2 `app_keys` from bytes

- **Repo/paths:** `server/src/aweb/app_registry.py`, new migration
  `team_app_keys (team_id, app_id, origin, digest, key_id, did_key, purposes,
  created_at, revoked_at)`, `server/src/aweb/cli.py` (reseed covers app keys).
- **Contents:**
  - `manifest_registration()` reads v2 `app_keys: [{kid, did_key, purposes}]`
    with a strict reader held to C3's interpreter vectors.
  - The rows follow acgh.8's rules: first `did_key` kept, `409` on conflict,
    one-way revocation, unknown purpose labels stored and granting nothing.
  - The `app-event` purpose also accepts a `team_app_keys` row declaring
    `app-event`.
- **Acceptance:**
  - only bytes-declared keys are registered;
  - another team's keys are never active;
  - reseed recreates the rows from bytes;
  - a v2 app emits with an `app_keys` key, and its `event_emitters`-era key
    stays `app-event` only.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-b1, G1-b2a, and D1 C3 freezing the `app_keys` shape and
  its interpreter vectors (aweb-acgg.9).
- **Review:** reviewer plus Athena.

### G1-b3: key revocation (team and operator)

- **Repo/paths:** `server/src/aweb/routes/apps.py`, `server/src/aweb/cli.py`.
- **Contents:**
  - `POST /v1/apps/{app_id}/keys/{kid}/revoke` sets the team row's one-way
    `revoked_at` under the team's install authority (F6 admin policy), for
    emit keys and app keys alike.
  - The post-mutation-hook event `app_key.revoked` (payload `app_id`, `kid`,
    `purposes`; `team_id` and the actor in the envelope, audit-substrate §A10
    at `98c1aa217`) is added by follow-up G1-b3e below.
  - An operator command, `aweb revoke-app-key --team <id> --app <id> --kid
    <kid>`, does the same for a named key: the remedy for a reseed
    `key_conflict`.
- **Acceptance:**
  - revocation takes effect on the next credential check;
  - a member without install authority is refused;
  - one team's revoke never touches another team's rows;
  - the operator audit row is written in the revoke transaction or not at all;
  - nothing reactivates a revoked key.
- **Done-signal:** SHA ACKed, landed.
- **Audit:** the team route and the operator command both write the
  append-only operator audit row (`record_coordination_audit` in
  `server/src/aweb/audit.py`, or its successor) in the same transaction as
  `revoked_at`. That row is required from the first landing, so a revocation
  never exists without an audit record and this task does not wait on the
  hooks outbox.
- **Depends on:** acgh.8 landed; F6's admin policy (aweb-acgg.5) for the
  team route.
- **Follow-up G1-b3e:** once aweb-acgh.1's core post-mutation-hook outbox
  (S2) lands, the revoke also enqueues `app_key.revoked` in the same
  transaction, with a test that the event and `revoked_at` commit together or
  not at all. Review: reviewer plus Athena.
- **Review:** reviewer plus Athena.

### G1-b4: grant status read

- **Repo/paths:** `server/src/aweb/routes/apps.py`, vector
  `test-vectors/app-read-credential-v1.json`.
- **Contents:**
  - `GET /v1/apps/self/grant` under `app-grant-read` returns the design's §3
    shape: team and app from the credential; `installation_id` and
    `generation` null until F6; `as_of`; `max_age_seconds` set by
    configuration with a ceiling of 60.
  - `403 app_key_not_registered` when no key for that purpose is active.
- **Acceptance:**
  - the vector's positive and cross-purpose negative cases are verified by
    server and client;
  - a digest change is visible on the next read;
  - the response never includes another app or team.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-b1, G1-b2b.
- **Review:** reviewer plus Athena.

## C. `aweb_naapp.runtime` clients

### G1-c1: one app-key loader

- **Repo/paths:** a dependency-light `aweb_naapp` module outside `runtime`
  (for example `aweb_naapp.keys`), importable with the standard library and
  `pynacl` only, as the outbox is, because core loads its own hook-producer
  key with it (aweb-acgh.1 build). `runtime/settings.py` only wires
  configuration to it.
- **Contents:** decision 10.
  - Configuration maps kid → key file.
  - Which purposes a kid may sign comes from the pinned manifest's
    `app_keys`.
  - Loading happens once at runtime startup and fails startup on a missing,
    unreadable, malformed, group- or world-writable, or non-regular file.
  - One format: 64 hex characters with one optional trailing newline.
  - Key material never appears in logs, errors, repr or settings dumps.
  - The released `*_APP_EMIT_KEY_SEED_HEX` value is accepted for the
    `app-event` key only.
- **Acceptance:**
  - each refusal is tested;
  - a test proves the key material is absent from captured logs, error text
    and repr;
  - Folio's released variable still loads its emit key;
  - a guard test proves the module imports without the `runtime` extra
    (stdlib and `pynacl` only), as the docs-surface guard does.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** nothing. The runtime seat proposed building it with the
  outbox emit piece (aweb-acgh.6).
- **Seat:** aweb-expert (aweb-expert-naapp-runtime).
- **Review:** reviewer plus Athena (key handling).

### G1-c2: team-server discovery client

- **Repo/paths:** `naapp-lib/src/aweb_naapp/runtime/` (a discovery module).
- **Contents:** the §1 chain.
  - The team id is a lookup key only.
  - The registry is the verifier's configured registry
    (`NaappSettings.awid_registry_url`). A domain whose `_awid` statement
    names a different registry is refused.
  - The current team key comes through the existing `AWIDTeamCache`, one
    instance per registry origin.
  - The record is verified with no redirects.
  - Three distinct refusals: `team_server_unpublished`,
    `team_server_key_mismatch` and `authority_unavailable`.
  - A cache of at most 60 s, keyed on (registry origin, team id), with no
    expired fallback.
- **Acceptance:** tests against a real AWID service with records published
  through G1-a1's route cover:
  - a valid record;
  - an unpublished team;
  - a stale key after rotation;
  - a far-future record;
  - a registry mismatch;
  - an outage, with the AWID service stopped.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-a1.
- **Review:** reviewer plus Athena.

### G1-c3: app credential signer and `TeamGrantSource`

- **Repo/paths:** `naapp-lib/src/aweb_naapp/runtime/`.
- **Contents:**
  - `AppCredentialSigner(app_id, kid, key, purpose)`, using the G1-c1 loader.
    It refuses at startup a purpose that the kid is not declared for in the
    app's pinned bytes.
  - `TeamGrantSource.grant_for(team_id)` implements B1's `GrantSource`
    (`runtime/authorization.py`). It returns a `Grant` with `fresh_until` set
    to receipt time plus `min(max_age, 60)`, and `None` for not granted.
  - It raises `GrantUnavailable` for an outage, unpublished discovery, a key
    mismatch or a malformed answer.
  - An expired entry is never served, the refresh is bounded by a timeout,
    concurrent misses are coalesced, and `app_id`, `origin` and `digest` are
    checked against the app's identity.
- **Acceptance:** byte-parity with `app-read-credential-v1.json`; B1's
  verifier returns `503` for unavailable and `403` for not granted, through
  real HTTP to a real aweb server in tests.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-b4, G1-c1, G1-c2.
- **Review:** reviewer plus Athena.

## D. Hook resolution

### G1-d1: server resolution endpoints

- **Repo/paths:** `server/src/aweb/routes/apps.py` (or a hooks route module).
- **Contents:** from the design's §4, under `hook-resolve`:
  - registrations, authorized by an active production;
  - productions with hook-purpose keys only, authorized by an active
    registration;
  - own bindings by `binding_id` or by hook;
  - client-class registrations for a team-auth v2 member;
  - anonymous `GET /v1/hooks/producer-keys` with validity windows.
  Every response carries `as_of` and `max_age_seconds`.
- **Acceptance:**
  - every authorization rule is tested in both directions;
  - an emit-only or usage key is never listed;
  - an unknown catalog, version or hook resolves to nothing;
  - a revoked or superseded binding disappears on the next read.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:**
  - the hooks lane's `app_hook_bindings` table and owner activation
    (aweb-acgh.1 build);
  - F6's `installation_id` and generation (aweb-acgg.5);
  - G1-b1;
  - G1-b2b.
- **Review:** reviewer plus Athena.

### G1-d2: `HookResolver` client

- **Repo/paths:** `naapp-lib/src/aweb_naapp/runtime/`.
- **Contents:**
  - `registrations(team_id, catalog, version, hook)`, `productions(…)` and
    `own_bindings(…)`;
  - the core origin anchored per team through G1-c2 and never taken from an
    event;
  - re-resolution when the team-server record changes;
  - a cache of at most 60 s, failing closed.
- **Acceptance:** tests through real HTTP to a real aweb server with
  activated bindings.
- **Done-signal:** SHA ACKed, landed.
- **Depends on:** G1-d1, G1-c2, G1-c3.
- **Review:** reviewer plus Athena: it authenticates with the `hook-resolve`
  credential, and its answers decide where a producer delivers and which keys
  a target accepts.

## E. Real-stack acceptance

### G1-e1: discovery and grant, end to end

- **Repo/paths:** a new script under `scripts/e2e/`, reusing the folio-wakes
  compose stack (AWID, aweb, Folio) plus one generic fixture naapp built on
  `aweb_naapp.runtime`.
- **Scenario:** no mocks, with disposable identities.
  1. A BYOT team publishes its server record with `aw id team set-server`.
  2. The fixture naapp discovers the server and reads its grant.
  3. A member call passes B1 with that grant.
  4. A digest change, then a per-team key revoke, take effect within
     `max_age`.
  5. An unpublished team gets `503`, and a rotated team key without
     republication gets `503 team_server_key_mismatch`.
  6. Stopping AWID or aweb gives `503` after the cache bound, never a stale
     grant.
- **Done-signal:** green run with evidence, harness shown failing against a
  deliberately broken build.
- **Depends on:** G1-a2, G1-b4, G1-c3.
- **Review:** reviewer.

### G1-e2: hook resolution, end to end

- **Scenario:**
  1. A producer fixture resolves an owner-activated registration and delivers
     to it.
  2. The target confirms its own binding and the producer's hook-purpose key.
  3. Revoking the binding stops delivery within `max_age`.
- **Depends on:** G1-d2 and the hooks lane's delivery path.
- **Review:** reviewer.

## Hosted-side items

The OSS contract states each of these as a generic requirement on a custodial
deployment. They map onto existing board tasks; no new hosted item is
created here.

| Item | Requirement | Board task | Depends on |
| --- | --- | --- | --- |
| H1 | Publish an `aweb.team-server/1` record for every team whose controller key the deployment holds: at creation, on any move and on team key rotation, in the same operation. Backfill all existing teams before any naapp depends on discovery. No interim pin or default. | L6, aweb-acgg.31 | G1-a1 |
| H2 | The hosted install path sends the exact manifest bytes with every install, as `aw` does after G1-b2a, and reads no `app_registry_emit_keys` or `app_registry_event_types` rows. | L1, aweb-acgg.21 | G1-b2a; acgh.8 for the second half |
| H3 | Hosted admin controls for per-team key revocation call the G1-b3 route under the hosted admin policy. | L1, aweb-acgg.21 | G1-b3, F6 |
| H4 | Deploy steps for each server release that migrates registrations: save installed apps' manifest bytes before migrating, reseed right after, report `key_conflict` teams. Under Juan's standing rule a release deploys once its last reviewer approves; these steps are part of that operations deploy. | operations (Hestia), not a build task | each such release |

## Cross-lane dependencies

| Dependency | Needed by |
| --- | --- |
| aweb-acgh.8 landed and released | G1-b1, G1-b2a, G1-b3 |
| aweb-acgh.1 hook contract (catalog with `app_key.revoked`, envelope, binding vectors) and core post-mutation-hook outbox | G1-b3e, G1-d1 |
| aweb-acgh.1 `app_hook_bindings` and owner activation | G1-d1 |
| aweb-acgh.6 runtime extraction (outbox emit) | G1-c1 (built together) |
| aweb-acgh.4 approvals and passkeys | none here |
| D1 C3 (aweb-acgg.9) manifest v2 `app_keys` shape and interpreter vectors | G1-b2b |
| D1 F6 (aweb-acgg.5) installation identity, admin policy, uninstall | G1-b3 (route authority), G1-b4 (fields), G1-d1 |
| D1 L6 (aweb-acgg.31) custodial record publication and backfill | G1-e1 for hosted teams; any naapp depending on discovery for a hosted team |
| D1 L1 (aweb-acgg.21), L2 (aweb-abzo), L3 (aweb-acgg.22) | consume G1-c3 and G1-d2; nothing here waits on them |
