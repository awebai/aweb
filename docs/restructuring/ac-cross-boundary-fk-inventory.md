# ac cross-boundary FK + overlay inventory (SOT §8.1 appendix)

Reference artifact for the restructuring SOT (`../restructuring-sot.md` §8).
Grounded in `ac/backend/src/aweb_cloud/migrations/` as of 2026-06-15. This is the
**highest-risk mechanical step** in the decomposition: every FK below crosses a
schema boundary and must be removed or converted to a logical reference before
the schemas can live in separate services.

## 1. Cross-boundary foreign keys (30)

Schemas: `aweb_cloud` (SaaS/control-plane), `server` (cloud coordination),
`aweb` (OSS canonical), `awid`.

| # | From `table.column` (schema) | → To `schema.table.column` | File:line | On delete |
|---|---|---|---|---|
| 1 | byot_custodial_identity_authorizations.server_team_id (aweb_cloud) | server.teams.id | 001:2334 | CASCADE |
| 2 | byot_custodial_identity_authorizations.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 001:2342 | CASCADE |
| 3 | cloud_agent_certificates.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 001:2350 | CASCADE |
| 4 | cloud_custodial_keys.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 001:2358 | CASCADE |
| 5 | cloud_workspace_metadata.server_team_id (aweb_cloud) | server.teams.id | 001:2374 | CASCADE |
| 6 | cloud_workspace_metadata.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 001:2382 | CASCADE |
| 7 | consumer_contact_invites.inviter_team_id (aweb_cloud) | server.teams.id | 001:2390 | CASCADE |
| 8 | managed_namespaces.team_id (aweb_cloud) | server.teams.id | 001:2446 | CASCADE |
| 9 | mcp_oauth_grants.agent_id (aweb_cloud) | aweb.agents.agent_id | 001:2478 | CASCADE |
| 10 | mcp_oauth_grants.team_id (aweb_cloud) | server.teams.id | 001:2494 | CASCADE |
| 11 | oss_join_requests.team_id (aweb_cloud) | server.teams.id | 001:2630 | CASCADE |
| 12 | oss_public_teams.team_id (aweb_cloud) | server.teams.id | 001:2646 | CASCADE |
| 13 | principals.agent_id (aweb_cloud) | aweb.agents.agent_id | 001:2662 | CASCADE |
| 14 | spawn_invite_tokens.created_by_agent_id (aweb_cloud) | aweb.agents.agent_id | 001:2686 | CASCADE |
| 15 | spawn_invite_tokens.team_id (aweb_cloud) | server.teams.id | 001:2710 | CASCADE |
| 16 | team_invitations.team_id (aweb_cloud) | server.teams.id | 001:2726 | CASCADE |
| 17 | team_members.team_id (aweb_cloud) | server.teams.id | 001:2734 | CASCADE |
| 18 | team_repos.team_id (aweb_cloud) | server.teams.id | 001:2750 | CASCADE |
| 19 | cloud_custodial_encryption_keys.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 002_custodial_encryption_keys.sql:31 | CASCADE |
| 20 | a2a_gateway_identities.workspace_id (aweb_cloud) | aweb.workspaces.workspace_id | 003_a2a_gateway_routes.sql:40 | SET NULL |
| 21 | a2a_gateway_routes.gateway_identity_id (aweb_cloud) | aweb_cloud.a2a_gateway_identities.id | 003:148 | RESTRICT |
| 22 | a2a_gateway_routes.owner_team_id (aweb_cloud) | server.teams.id | 003:152 | CASCADE |
| 23 | aweb.api_keys.team_id (aweb) | server.teams.id | aweb_overlay/001:235 | CASCADE |
| 24 | aweb.api_keys.agent_id (aweb) | aweb.agents.agent_id | aweb_overlay/001:236 | (no action) |
| 25 | aweb.spawn_invite_tokens.team_id (aweb) | server.teams.id | aweb_overlay/001:263 | CASCADE |
| 26 | aweb.spawn_invite_tokens.created_by_agent_id (aweb) | aweb.agents.agent_id | aweb_overlay/001:264 | CASCADE |
| 27 | aweb.replacement_announcements.team_id (aweb) | server.teams.id | aweb_overlay/001:289 | CASCADE |
| 28 | aweb.replacement_announcements.old_agent_id (aweb) | aweb.agents.agent_id | aweb_overlay/001:290 | CASCADE |
| 29 | aweb.replacement_announcements.new_agent_id (aweb) | aweb.agents.agent_id | aweb_overlay/001:291 | CASCADE |
| 30 | aweb.dns_namespaces.scope_id (aweb) | server.teams.id | aweb_overlay/001:183 | SET NULL |

Note #21 is intra-`aweb_cloud` (listed for completeness with the a2a cluster).
The other 29 are genuine cross-schema edges. (#9/#10 share a row, etc. — the
count is of constraints, not tables.)

## 2. `aweb_overlay` alterations to canonical `aweb` tables

The overlay (`aweb_overlay/001_initial.sql`) mutates schema the OSS `aweb`
package owns. All of this must move to control-plane-owned tables/projections to
"dismantle the overlay" (SOT §8 step 1).

### 2A. `aweb.agents` — 11 cloud columns added (lines 29–76)
`server_team_id`, `did`, `public_key`, `stable_id`, `access_mode`, `custody`,
`signing_key_enc`, `successor_agent_id`, `program`, `context`, `team_cert_blob`.
Plus 4 indexes (`idx_agents_server_team_alias_unique_active`,
`idx_agents_server_team_did_unique_active`, `idx_agents_did`,
`idx_agents_stable_id`).

### 2B. `aweb.messages` / `aweb.chat_messages` — `signing_key_id` added (lines 107, 111)

### 2C. `aweb.tasks.parent_task_id` — FK made DEFERRABLE (lines 120–127)
Drops `tasks_parent_task_id_fkey`, re-adds it `DEFERRABLE INITIALLY IMMEDIATE`
(for cloud restore/cutover circular-restore patterns). **This behavior must be
preserved wherever the tasks schema lands** — see SOT §12 milestone-7 trap.

### 2D. 7 tables created *inside* the `aweb` schema by the overlay
`did_aw_mappings`, `did_aw_log` (identity rotation chain), `dns_namespaces`,
`public_addresses` (namespace/address registry), `api_keys`,
`spawn_invite_tokens`, `replacement_announcements`. These are control-plane
concerns living in the core schema — relocate to control-plane ownership.

## 2.5 Staging tag: 8a (now) vs 8b (gated by a later split)

The decomposition is **not self-contained** (SOT §8/§12.8). Each FK and overlay
column must be tagged:

- **8a — doable now:** edges/columns touching identity/namespace/control-plane
  tables only (e.g. `aweb.agents` identity cols; FKs to `server.teams` from
  cloud-owned tables; namespace/address tables).
- **8b — gated by a later split:** anything touching the **split-last messaging
  tables** (`messages`, `chat_messages`, `conversations*`, `chat_*`) or the
  **split `workspaces` table** — these can only finalize once messaging (§12.10)
  and the workspaces split land. Notably the overlay's `signing_key_id` on
  `messages`/`chat_messages` (§2B) and any workspace-keyed FKs (#2,3,4,6,19,20)
  are 8b.

TODO before the decomposition milestone: add an explicit `8a`/`8b` column to the
table in §1 and the alterations in §2, so m8 is never over-promised as complete
overlay/FK removal.

## 3. Decomposition implication

Because of CASCADE deletes and the dense `aweb_cloud → server.teams` /
`aweb_cloud → aweb.workspaces` / `aweb_cloud → aweb.agents` web, splitting the
schemas into separate services requires: (1) convert these FKs to logical
references keyed on `aweb_team_id` / `workspace_id` / `agent_id`; (2) replace
CASCADE semantics with explicit application-level cleanup; (3) stage with
backfill + verification before dropping any FK; (4) preserve the
`tasks.parent_task_id` DEFERRABLE behavior.
