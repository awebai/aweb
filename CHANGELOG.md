# Changelog

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
