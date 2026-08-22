# Changelog

## Unreleased

### Migration compatibility

- The immutable published `011_chat_message_reads.sql` migration can now run on
  existing databases whose legacy read receipts outlived their chat participant.
  An append-only pre-shim preserves the participant foreign key while filtering
  those orphan backfill rows; migration 012 removes the temporary filter,
  repeats the backfill with an explicit participant guard, and restores the
  same final constraint set for fresh and already-011-applied databases.

- New additive migration `017_agents_certificate_id.sql` records the team
  certificate that admitted each agent projection (nullable column; rows
  created before it heal at their next certificate-authenticated connect or
  request). Required by the revocation enforcement below.

### Server compatibility

- The chat mark-read HTTP endpoint and both canonical/legacy MCP tools now
  accept the deployed-client `up_to_message_id` watermark, the upgraded-client
  `message_ids` list, or both. When both are present, the exact ID list takes
  precedence. This keeps published aw, Claude channel, Pi, and external MCP
  clients compatible with a server-first rollout while allowing future clients
  to send an expand/contract payload that works across server versions.
- The silent-loss race is fixed only for upgraded clients that send every
  presented `message_ids` value. Older clients that send `up_to_message_id`
  retain their existing range-resolution race because the server must infer
  the read set from the watermark; this is their prior behavior, not a new
  regression.

- Certificate revocation is now enforced on every messaging auth form. The
  agents projection records its admitting certificate, and identity-only,
  grant, and MCP identity-auth requests check it against the AWID registry's
  revocations: a revoked member keeps its DID-scoped mailbox but loses team
  context (team attribution, alias sends, team-gated behavior), and a grant
  whose issuing certificate is revoked is refused. Previously a revoked local
  member whose projection survived could keep acting under its team alias by
  omitting the certificate header. Consequences to plan for: identity-auth
  requests that carry team context now share the certificate path's fail-closed
  posture toward the registry (503 when it is unreachable past the cache's
  stale window), and deployments should configure `AWID_SERVICE_TOKEN` so
  revocation refreshes bypass the registry's public per-IP rate limits.
  Limitation: hosted-custody members whose certificates never reach the AWID
  registry are not covered by this check — the staged existence requirement
  below closes that gap once hosted anchoring has backfilled.
- Staged existence-required certificate verification, default off
  (`AWEB_REQUIRE_REGISTERED_CERTIFICATES`). An unregistered team certificate is
  unrevocable — the registry's revocation set can never name it — so once the
  hosted anchoring backfill completes, "not registered at the AWID registry"
  becomes a verification failure rather than a pass by omission. When enabled,
  the presented-certificate path (team routes, connect, MCP), the identity-only
  paths (HTTP and MCP), and a session grant's issuing certificate all require
  registry existence, with verdicts distinct from signature failure and from
  revocation (`Certificate not registered`, `grant issuing certificate not
  registered`). The existence read rides the cached registry client's existing
  team-certificates tier (10-minute freshness, stale-while-revalidate), adding
  no per-request registry round-trip, and fails closed on registry
  unavailability exactly as the revocation check does. Off by default and
  byte-identical to previous behavior with zero added registry calls; enabling
  it in production is an ops act gated on the anchoring backfill's failure
  enumeration being empty or individually remediated.
- Revocation cache refreshes read the complete paginated set. Timestamp-only
  incremental refresh is unsafe because PostgreSQL timestamps reflect
  transaction start: a revocation waiting on a row lock can commit after a
  refresh with an older timestamp and be skipped by a `since` cursor. Fresh
  TTL, stale window, the 15-minute registry-outage grace and its logging,
  fail-closed behavior, and Redis retention are unchanged; a partly-read
  refresh never restamps the cached entry's age.
- Registry cache: background-refresh failures for the team-certificate tier now
  log at warning level with the team, the age of the last-known-good list being
  served, and the underlying error, matching the revocation tier. That tier
  gates every authenticated request once
  `AWEB_REQUIRE_REGISTERED_CERTIFICATES` is enabled, so a registry outage is no
  longer silent there. Logging only: no cache TTL, retention, or outage grace
  changed, and tiers that opt out keep their previous debug-level behavior.
- The AWID team revocation list is completely enumerable: the route paginates
  with a `(revoked_at, id)` cursor and reports `has_more`/`next_cursor`, and
  the Python registry client follows it to the end (with a best-effort `since`
  fallback against pre-pagination servers). Previously the oldest 1000 rows
  were returned with no truncation signal and consumed as the complete set. A
  legacy client that sends no pagination parameters still gets its historical
  1000-row page, never a shorter one. Revocation lists are now cached for 60
  seconds (hard worst case 120 through stale-while-revalidate) instead of 10
  minutes, so a revocation takes effect on enforcement within about a minute;
  raising that constant is a trust-model change (see trust-model.md,
  "Threat-model rulings").
- Registry-outage grace for team revocation reads (owner-adopted 2026-08-17):
  the cached registry client retains the last-known-good revocation set for
  fifteen minutes beyond freshness and, when a refresh fails, serves it while
  the data is at most fifteen minutes old, logging each occurrence at warning
  level with the team, the data's age, and the error; past that age the read
  fails closed (503 upstream) exactly as before. The 60-second fresh TTL, the
  120-second stale-while-revalidate window, and every other cache tier's
  retention are unchanged; the fifteen-minute bound is a pinned constant with
  no configuration knob.
- awid service: team visibility is now enforced on the read side. For teams
  not marked `public`, team get, certificate list, member resolve, and
  revocation list require a same-team path-signature (the certificate
  blob-fetch scheme, from the team controller key or an unrevoked member key)
  or the trusted `AWID_SERVICE_TOKEN`; unauthorized reads return 403 with the
  stable error code `team_private`. Domain team enumeration omits private
  teams for anonymous and unprivileged signed callers. New teams default to
  private at the schema level (unchanged, now load-bearing). Deployments
  running aweb revocation enforcement against private teams must configure
  `AWID_SERVICE_TOKEN`; the blob-fetch route and the controller-signed
  visibility setter are unchanged.

### CLI compatibility

- `aw team invite` now prints the complete porcelain `aw team join` command,
  and `aw team join` installs membership and connects the current workspace in
  one step using the invite's embedded aweb service URL. Newly printed hosted
  invites use a versioned, backward-compatible envelope around the existing
  opaque bearer token; legacy hosted tokens and local-controller tokens remain
  accepted. `--no-connect` preserves an explicit membership-only path and
  prints the exact recovery command. The low-level `aw id team accept-invite`
  primitive remains membership-only.
- The aw CLI now sends exact chat read IDs first and retries one rejected,
  well-formed request with the legacy newest-ID watermark. Failed fallbacks
  retain the original 4xx, while malformed IDs make only the authoritative
  server request. On older servers the watermark deliberately retains legacy
  range semantics and may mark unpresented messages before it; that trade
  retires when the server accepts exact IDs.
- Session-lease commands now turn a 404 from their lease routes into an explicit
  requirement for aweb server 1.26.28 or later.

- `aw check` on a healthy install now reports `Doctor: ok`. The verdict is
  computed over checks that actually ran: deliberately skipped checks (the
  offline default, or a check with no safe probe) keep per-check status
  `unknown` with `detail.skipped: true`, are counted in a new top-level
  `skipped_checks` field, and no longer force the verdict to `unknown`; `info`
  folds into `ok`. Human output marks them `[skipped]` and names
  `aw check --online`. Consumers of the doctor.v1 JSON `status` field should
  note the tightened semantics (documented in support-tools.md).
- `aw mail show` uses the same certificate-first client selection as
  send/reply, and identity-auth reads verify current-team senders through a
  certificate-authenticated roster resolver when the workspace holds a
  certificate. Previously `aw mail show` alone rendered every verified
  current-team sender as `[verification stale]` on self-hosted pairs. Without
  any certificate the fail-closed stale verdict still applies.
- Team accept/enroll/provision paths now publish the E2E encryption-key
  assertion (to AWID for global identities, to the aweb service where a
  workspace binding exists) and record `published_at`; a publish failure warns
  loudly with the remedy instead of failing the recorded membership. A new
  offline doctor check, `identity.e2ee.assertion_published`, warns when a
  publishable identity has never recorded a publish; `aw id encryption-key
  setup` republishes. Previously provisioning created the key locally and
  never published, leaving counterparties nothing to encrypt to.
- BYOT CLI reads work against private teams. `aw team agent-status`, `aw id
  team members`, agent retirement, and the roster alias fallback now attach
  the same path-signature the certificate blob fetch uses when the invoking
  workspace holds a usable key — its own identity signing key, falling back
  to a locally held team controller key, tried in that order and advancing
  only on the registry's visibility refusal. Public teams and every non-403
  failure are unchanged, and a `team_private` refusal now prints what to do
  (run from a workspace holding a certificate for the team, or ask the team
  controller, who sets visibility) instead of a raw HTTP error.

### Channel compatibility

- Chat mark-read sends exact presented IDs on current servers. When a server
  returns a 4xx for a well-formed exact request, the channel retries once per
  chunk with the legacy watermark; malformed exact requests still surface the
  server's original error without retrying, and a failed fallback preserves the
  original 4xx. This lets auto-updated channels work with older self-hosted
  servers regardless of validation-error wording. The fallback deliberately
  retains old-client range semantics: an old server may mark unpresented
  messages before the watermark read. That trade retires itself when the server
  upgrades and accepts the exact-ID fast path.

## v1.8.1

### awid/aweb separation

- Team membership state moved from `.aw/workspace.yaml` to `.aw/teams.yaml`.
  All `aw id team` commands (add, switch, list, leave, cert show) now operate
  on `teams.yaml` only, fully independent of aweb. Existing workspaces are
  migrated lazily on first access.
- `TeamMembership` is a standalone awid struct with four fields: `team_id`,
  `alias`, `cert_path`, `joined_at`. No aweb concepts (`workspace_id`,
  `role_name`) leak into team state.
- `aw id` registry resolution no longer reads `workspace.yaml` or `AWEB_URL`.
  The chain is: `identity.yaml` registry_url, `AWID_REGISTRY_URL` env var,
  DNS discovery, default `api.awid.ai`.
- `AWID_REGISTRY_URL=local` is now rejected with a clear error.
- DNS-discovered registry URLs are persisted in `identity.yaml` so BYOD
  identities do not re-do DNS on every CLI session.
- `claim-human` moved from the Identity command group to Workspace Setup.

### Identity model

- `identity.yaml` is now written only for persistent identities. Ephemeral
  agents (local init, hosted default, add-worktree) do not create it.
- The messaging client falls back to `.aw/signing.key` when `identity.yaml`
  is absent, deriving the DID via `ComputeDIDKey`.
- `aw id` read-only commands (`resolve`, `verify`, `namespace`) no longer
  require `signing.key` when loading identity for registry URL lookup.
- Validation hardening: empty/malformed `identity.yaml` fails loudly,
  persistent agents with missing `identity.yaml` fail loudly, ephemeral
  fallback rejects certs with empty `member_did_key`.

### Local namespace and onboarding

- awid reserves `local` as a domain that skips DNS verification by policy.
  `namespace_type` column dropped from the awid schema entirely.
- `aw init` with a localhost awid registry automatically uses the implicit
  local flow: namespace `local`, team `default`, ephemeral identity, no
  wizard.
- `--awid-registry` and `--aweb-url` CLI flags override env vars and
  defaults on `aw init`.
- `aw init` with `AWEB_API_KEY` env var exchanges a one-time HMAC bearer
  token for a team certificate. The token is never written to disk. Cert
  signature, DID binding, custody, and lifetime are all validated.
- Self-hosting guide rewritten for two audiences: local quickstart and
  company DNS deployment.

### Signed payload and messaging fixes

- Signed payload `from` field now uses the team cert alias in cert-auth
  mode, not the identity-derived address name. Fixes 422 mismatch when
  identity name differs from team alias.
- Ephemeral agents no longer register DID or address at awid, fixing
  bidirectional mail delivery between ephemeral agents.
- Default coordination server discovery: cert-based `aw init` defaults to
  `app.aweb.ai/api` when the team registry is `api.awid.ai`.
- `normalizeAwebBaseURL` no longer strips `/api` from user-provided URLs.

### New commands

- `aw id team request --team <team_id> --alias <alias>`: prints the exact
  `aw id team add-member` command the team owner should run. Pure awid,
  no workspace dependency.
- `aw id team add-member --did <did:key>`: adds a team member by DID
  (for ephemeral agents without addresses). Supports `--lifetime`,
  `--did-aw`, `--address` for persistent agents.
- `claim-human --username <override>`: works for any awid-registered
  domain, not just `*.aweb.ai`.
- `aw id team reissue-cert <alias>`: mint, register, and optionally install a
  fresh team certificate for an existing member whose signed blob is lost or
  was never registered — same member did:key, alias, and identity scope, new
  certificate id and issued_at. Revokes the currently registered certificate
  first (so the registry's one-active-certificate-per-alias constraint is
  never violated), registers the fresh one after, and is safe to re-run
  across a partial failure. Requires the locally held team controller key;
  this is the blob-lost remedy from the hosted-certificate-anchoring
  contract and is not key rotation — for a lost or compromised member key,
  use `aw team replace-key`.

### Removed from CLI surface

- `aw spawn create-invite` and `aw spawn accept-invite` are no longer
  user-facing commands. The invite code is used internally by
  `aw workspace add-worktree`.

### Server fixes

- MCP auth middleware, team auth, and messaging auth now accept both
  `DatabaseInfra` and raw `AsyncDatabaseManager`, fixing crashes on the
  cloud MCP mount path.

## v1.8.0

This release note covers the user-visible changes between the `v1.7.0`
entry above and `main` at `ec5db2c` on 2026-04-11.

### Upgrade checklist

- Reinitialize or migrate any legacy single-team `.aw/workspace.yaml`
  into the canonical multi-team workspace shape before relying on
  cross-team identity-scoped messaging.
- If you store or validate awid reachability values, update them to the
  canonical set: `nobody`, `org_only`, `team_members_only`, `public`.
- If you construct signed messaging payloads outside the shipped CLI,
  update them to match the enforced signed envelope and recipient
  binding rules described below.
- Regenerate any vendored CLI help or scripted `aw --help` snapshots
  against the current Cobra tree.

### Breaking changes

- Messaging is now identity-scoped end to end. Mail, chat, pending,
  conversations, MCP mail/chat, and channel wake behavior are bound to
  persistent identity (`did:aw`) instead of team-local agent rows.
- Messaging routes now fail closed on signed-payload mismatches. Mail
  and chat reject requests when the outer request disagrees with the
  signed envelope for content, sender identity, recipient identity, or
  chat behavior modifiers.
- Messaging routes now fail closed on conflicting recipient selectors.
  If `to_stable_id`, `to_did`, `to_address`, `to_agent_id`, or
  `to_alias` do not resolve to the same target, the request returns 422
  instead of accepting a precedence override.
- Public address reachability uses the cleaned-up awid enum model:
  `nobody`, `org_only`, `team_members_only`, `public`.

### New features and user-visible behavior changes

- Multi-team workspaces are now the canonical CLI model. Workspaces can
  carry the new team-binding shape, legacy worktrees can be migrated in
  place, and docs/help were updated around the team-scoped workspace
  model.
- Self-hosted local bootstrap now has an implicit localhost path. A
  localhost `awid` registry reserves the `local` namespace, and `aw init`
  accepts explicit `--awid-registry` / `--aweb-url` overrides so one
  command can create the local identity, join `default:local`, and bind
  the workspace.
- Dashboard reads now expose the full team event stream via
  `GET /v1/teams/{team_id}/events/stream`, including `task.created`,
  `task.status_changed`, `task.claimed`, `task.unclaimed`,
  `message.sent`, `agent.online`, and `agent.offline`.
- Dashboard task and agent surfaces were extended with the fields needed
  by the hosted dashboard: claims route, task filtering/pagination,
  creator/assignee detail, parent task IDs, labels, blocker counts,
  updated timestamps, richer agent summaries, and consistent event
  snapshots.
- `GET /v1/conversations` is now identity-scoped under MessagingAuth,
  so human `did:key` / `did:aw` traffic shows up consistently across
  mail and chat instead of disappearing behind team-local filtering.
- Mutation event contexts now carry canonical caller `did:aw` for
  downstream billing and audit attribution.

### Fixes worth calling out

- Signed messaging behavior is now consistent across CLI, REST, SSE,
  MCP, and channel consumers. That includes wait/reply modifiers,
  stable/current DID handling, exact-message wake fetches, and
  second-precision signing timestamps in channel clients.
- Recipient binding now survives local key rotation and current-DID
  targeting, so inbox/history/pending surfaces keep stable sender and
  recipient identity labels across rotation.
- CLI chat/session resolution was hardened to fail closed on ambiguous
  alias/address collisions while still accepting equivalent rows for the
  same identity. Pending, notify, wake, formatter, and session lookup
  paths now share one identity model.
- More than 133 identity-routing and identity-labeling bugs were fixed
  across mail, chat, pending/wake handling, awid transport, and channel
  dispatch.
- Task and conversation routes were tightened to the current schema and
  auth contracts, including null-guarded task timestamps and
  identity-scoped conversation listing.

### Operator and deployment changes

- Team dashboard presence events now publish through the shared
  `team-events:{team_id}` Redis channel instead of being emitted only
  inside a single SSE consumer.
- The OSS docs were updated to describe both team-certificate auth and
  identity-only messaging auth, plus the current signed-payload and
  recipient-binding invariants.

## v1.7.0

This release note covers the user-visible changes between the last deployed
server tag, `server-v1.6.2`, and `main` at `dca0464` on 2026-04-09.

### Upgrade checklist

- Replace `aw init --server ...` with `aw init --url ...` or `AWEB_URL=...`.
- Replace `aw directory --namespace ...` with `aw directory --domain ...`.
- Replace `aw project create` with `aw id team create`.
- Replace `aw spawn accept-invite` with `aw id team accept-invite`.
- If you self-host awid, replace any `awid serve ...` invocations with
  `awid ...` or `uv run awid ...`.
- Re-run `aw init` in any worktree that still has a legacy `.aw/workspace.yaml`.
- If you query aweb tables or MCP tools directly, update `project_*` names to
  `team_*`.

### Breaking changes

- `aw init --server` was removed. Use `--url` or the `AWEB_URL` environment
  variable instead.
- `aw directory --namespace` was renamed to `--domain`. Old scripts now fail
  with Cobra's unknown-flag error until updated.
- `aw project create` was removed. Team creation is now `aw id team create`.
- `aw spawn accept-invite` was removed. Invite acceptance is now
  `aw id team accept-invite`.
- API-key coordination auth was removed. `AWEB_API_KEY` is no longer honored,
  Bearer fallback is gone, and generic coordination requests now use DIDKey
  signatures plus `X-AWID-Team-Certificate`.
- `.aw/workspace.yaml` now enforces the canonical binding shape and hard-fails
  on removed keys instead of silently scrubbing them. Removed keys include
  `server_url`, `api_key`, `did`, `stable_id`, `signing_key`, `custody`,
  `lifetime`, `project_id`, `project_slug`, `namespace_slug`, `identity_id`,
  `identity_handle`, `cloud_url`, `awid_url`, `role`, and other old
  compatibility fields. The fix is to reinitialize the worktree with
  `aw init`.
- Coordination naming is now team-scoped throughout the live surface.
  Database tables were renamed from `project_roles` and
  `project_instructions` to `team_roles` and `team_instructions`. MCP callers
  must pass `team_instructions_id` instead of `project_instructions_id`.
- `POST /v1/connect` now rejects alias collisions with HTTP 409 instead of
  silently overwriting the existing workspace row.
- `aw workspace status` no longer cleans up stale ephemeral identities
  client-side. Cleanup still happens, but it now goes through
  `DELETE /v1/workspaces/{workspace_id}` and the server owns the identity
  removal path.
- `awid serve` was removed. The awid registry CLI now uses Typer's
  single-command form, so self-hosted wrappers, Dockerfiles, and service units
  must invoke `awid --host ... --port ...` or `uv run awid ...` instead of
  `awid serve ...`.

### New features and user-visible behavior changes

- Fresh-directory onboarding was rebuilt around the team architecture model.
  `aw init` and `aw run <provider>` now support:
  - BYOD onboarding for self-hosted or custom-domain teams
  - hosted onboarding for `app.aweb.ai`, including the explicit `aw init --hosted` path
  - reconnecting from an existing `.aw/identity.yaml` plus `.aw/team-cert.pem`
- `aw connect --bootstrap-token [--address ...]` was added for the dashboard
  Add Agent bootstrap flow.
- `aw claim-human --email ...` was added for attaching an email address to a
  hosted account and unlocking dashboard/admin flows after verification.
- `aw workspace add-worktree [role]` was restored as the supported same-repo
  multi-worktree flow. It creates a sibling git worktree with its own
  ephemeral team certificate and connects it to the same team.
- `POST /v1/agents/suggest-alias-prefix` was added so alias allocation happens
  server-side and checks both live agents and workspaces.
- Dashboard reads now have a defined JWT-based auth contract via
  `X-Dashboard-Token` and `AWEB_DASHBOARD_JWT_SECRET`, including public-team
  anonymous reads and fail-closed visibility behavior on registry lookup
  errors.
- Certificate-based coordination auth is now the only supported OSS auth model
  across REST, SSE, MCP, and channel integrations, with revocation-list-aware
  validation.
- `DELETE /v1/workspaces/{workspace_id}` was added for server-owned stale
  ephemeral workspace cleanup.
- The MCP `whoami` tool was restored.

### Fixes worth calling out

- SSE and event-stream behavior were tightened so status/event streams survive
  the body-cache middleware correctly.
- Connect/reconnect behavior is stricter and safer:
  - existing `did:key` identities cannot silently reconnect under a different
    alias
  - connect no longer falls back from alias to role semantics
  - add-worktree now derives registry choice from team controller metadata
- Dashboard reads now keep the intended behavior during awid registry outages:
  anonymous public-team reads fail closed when visibility cannot be checked,
  while authenticated dashboard JWT reads continue to work.
- Garbage collection now deletes all 21 team-scoped tables in foreign-key-safe
  order. Earlier cleanup behavior was incomplete and could fail on teams with
  tasks, workspaces, or related coordination state.

### Operator and deployment changes

- `server/docker-compose.yml` now builds `awid` from the sibling repo path, so
  the compose stack requires the repo-root build context instead of a
  server-only subtree checkout.
- Removed environment variables:
  - `AWEB_API_KEY`
  - `AWEB_CUSTODY_KEY`
  - `AWEB_MANAGED_DOMAIN`
  - `AWEB_NAMESPACE_CONTROLLER_KEY`
- Added environment variable:
  - `AWEB_DASHBOARD_JWT_SECRET`
- The old awid migrate-from-aweb compatibility path was removed from the live
  awid service and schema setup.
