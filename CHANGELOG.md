# Changelog

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
