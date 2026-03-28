# Policy -> Role / Role -> Role Name Contract

Status: draft for `aweb-aaab.1`

Date: 2026-03-27

## Why This Exists

Today there are two different concepts using overlapping language:

- The project-wide, versioned coordination bundle is called a `policy`.
- The per-workspace / per-agent selector string is called `role`.

That is backwards. The selector string is only a pointer to one named role definition inside the project-wide bundle. The rename must make that distinction explicit without breaking mixed-version `aweb`, `aw`, and `aweb-cloud` deployments.

## Canonical Vocabulary

- `role_name`: the workspace / agent selector string, for example `coordinator` or `developer`
- `role definition`: one named entry in the `roles` map, keyed by `role_name`
- `project roles`: the versioned project-wide bundle that contains:
  - `invariants`
  - `roles`
  - `adapters`

Bare `role` is reserved for human-facing prose or for a single role definition in obviously local contexts. Machine-readable surfaces should use either `role_name` or `project_roles*`, never overloaded `role`.

## Canonical External Names

### REST / JSON

- Route prefix: `/v1/roles`
- Active endpoint: `GET /v1/roles/active`
- History endpoint: `GET /v1/roles/history`
- Create endpoint: `POST /v1/roles`
- Read-by-id endpoint: `GET /v1/roles/{project_roles_id}`
- Activate endpoint: `POST /v1/roles/{project_roles_id}/activate`
- Reset endpoint: `POST /v1/roles/reset`

Canonical machine-readable fields:

- `role_name`
- `selected_role.role_name`
- `agent_role_name`
- `current_role_name`
- `project_roles_id`
- `active_project_roles_id`
- `base_project_roles_id`

### CLI

- Project role bundle commands live under `aw roles`
- Workspace / agent selector commands live under `aw role-name`
- Canonical long flag for selector input is `--role-name`

### Config

- `.aw/workspace.yaml` stores `role_name`

## Type-Naming Rule

Reserve `ProjectRoles*` for the versioned project-wide bundle and `Role*` for a single named role definition.

Examples:

- `PolicyBundle` -> `ProjectRolesBundle`
- `ActivePolicyResponse` -> `ActiveProjectRolesResponse`
- `CreatePolicyResponse` -> `CreateProjectRolesResponse`
- `PolicyHistoryItem` -> `ProjectRolesHistoryItem`
- `PolicyRolePlaybook` -> `RoleDefinition`

This avoids the trap where `role_id` could incorrectly mean the ID of the whole versioned bundle.

## Naming Matrix

| Surface | Old name | Canonical name | Compatibility rule |
| --- | --- | --- | --- |
| Workspace / agent selector field | `role` | `role_name` | Accept both on input during transition; if both appear and differ, reject with `400` |
| Selected role payload | `selected_role.role` | `selected_role.role_name` | Emit both during transition; new writers use `role_name` |
| Active roles selection query param | `role` | `role_name` | Accept both query params during transition |
| MCP current agent selector | `agent_role` | `agent_role_name` | Emit both during transition |
| MCP current workspace selector | `current_role` | `current_role_name` | Emit both during transition |
| Top-level resource route | `/v1/policies` | `/v1/roles` | Old route remains as alias until downstream repos switch |
| Active top-level route | `/v1/policies/active` | `/v1/roles/active` | Old route remains as alias |
| History top-level route | `/v1/policies/history` | `/v1/roles/history` | Old route remains as alias |
| Create body base pointer | `base_policy_id` | `base_project_roles_id` | Accept both on input during transition |
| Response/versioned bundle ID | `policy_id` | `project_roles_id` | Emit both during transition |
| Project active pointer | `active_policy_id` | `active_project_roles_id` | Emit both during transition |
| History list field | `policies` | `project_roles_versions` | Emit both during transition if the response is machine-consumed |
| aw project bundle command | `aw policy show` | `aw roles show` | Old command remains alias |
| aw project role list command | `aw policy roles` | `aw roles list` | Old command remains alias |
| aw selector mutation command | `aw roles set` | `aw role-name set` | Old command remains alias |
| aw selector flag | `--role` | `--role-name` | Old flag remains alias |
| Local workspace config key | `role:` | `role_name:` | Read both, write only `role_name:` |

## Compatibility Policy

### General Rule

Use dual-read plus alias-emit first. Do not do a one-shot rename.

### Server HTTP / MCP

- Accept both old and new field names on input.
- Accept both old and new route prefixes.
- Emit both old and new renamed machine-readable fields for one compatibility window.
- When both old and new inputs are present:
  - if equal, accept
  - if different, reject with `400`

### CLI and Local Config

- Read both old and new names.
- Prefer canonical commands, flags, and config keys in help text and generated output.
- Write only canonical config keys.
- Keep old commands as aliases long enough for scripts and docs to be updated.

### Database / Physical Storage

Do not physically rename storage first.

Phase 1 and Phase 2 should allow internal storage to remain policy-named where that is the lowest-risk path:

- `server.projects.active_policy_id`
- `server.project_policies`
- `server.project_policies.policy_id`
- related triggers, indexes, and snapshot/import code

Physical storage renames are Phase 3 cleanup and should happen only after `aw` and `aweb-cloud` have landed on the alias-enabled public contract.

## Explicit Non-Goals

These names are out of scope and must not be renamed as part of this work:

- SaaS membership roles: `owner`, `admin`, `editor`, `viewer`
- Organization roles and invite roles
- ARIA `role` attributes in frontend code
- General English uses of the word "role" outside coordination naming

## Rollout Order

1. Approve this contract.
2. Land `aweb-aaab.2`: server `role` -> `role_name` compatibility layer.
3. Land `aweb-aaab.3`: canonical `/v1/roles` public surface plus aliases for `/v1/policies`.
4. Land `aweb-aaab.4`: `aw` canonical commands / flags / config with compatibility aliases.
5. Land `aweb-aaab.5`: `aweb-cloud` backend, dashboard, onboarding, and docs changes against the alias-enabled server.
6. Land `aweb-aaab.6`: docs sweep, e2e updates, and optional physical storage cleanup.

## Release Gates

### Gate A: Contract Approval

Required before any downstream rename implementation starts.

- Eve publishes this contract
- Alice reviews and signs off on the repo split and compatibility rules

### Gate B: Selector Rename Ready

Required before canonical `/v1/roles` work begins.

- `role_name` is supported on server inputs
- old `role` inputs still work
- no downstream repo is forced to switch yet

### Gate C: Public Roles Surface Ready

Required before `aw` and `aweb-cloud` switch.

- `/v1/roles*` exists
- `/v1/policies*` aliases still work
- new and old ID fields are both available in machine-readable responses

### Gate D: Downstream Migration Complete

Required before cleanup.

- `aw` uses canonical naming by default
- `aweb-cloud` no longer depends exclusively on old policy paths or old selector field names
- docs and e2e coverage are updated

### Gate E: Cleanup Approval

Required before removing aliases or physically renaming storage.

- mixed-version risk reviewed
- rollback path documented
- Alice agrees the cloud slice is no longer consuming deprecated names

## Implementation Notes By Repo

### aweb

- Server route module and response models currently live under `server/src/aweb/coordination/routes/policies.py`
- Workspace / agent selector fields currently remain `role` in workspaces, agents, presence, init, scopes, status, and MCP payloads
- MCP tools currently use `policy_show`, `roles_list`, `agent_role`, and `current_role`

### aw

- Client models currently live in `cli/go/policies.go`
- Commands are currently split awkwardly between `aw policy *` and `aw roles *`
- `.aw/workspace.yaml` currently stores `role`

### aweb-cloud

- Backend project creation imports `create_policy_version` / `activate_policy`
- Auth bridge currently hardcodes `/v1/policies*`
- Dashboard API/types and the `PoliciesPage` are policy-shaped
- Hosted identity / CLI setup flows currently load policy-defined roles into selector UIs

## Decisions Frozen By This Contract

- `role_name` is the canonical machine-readable selector name.
- The top-level versioned bundle is not renamed to bare `role_id`; use `project_roles*` names for that layer.
- `/v1/roles*` is the canonical public route family.
- Physical DB/table/column renames are deferred until cleanup unless a later implementation note explicitly proves they can be done safely earlier.
