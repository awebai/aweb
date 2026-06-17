# Core-surface shrink scorecard baseline

Status: prep baseline for extraction milestones; this does **not** open an
extraction track.

Grounded at repo state `f45c8516` (2026-06-17), cross-referenced with
`docs/restructuring-sot.md` §4 and
`docs/restructuring/oss-core-inventory.md`.

Purpose: every extraction Definition-of-Done should show a delta **down** from
this baseline. Moving a domain behind an app/container without shrinking these
core counts is a visible failure.

## Counting method

- **Tables** are the SOT §4 tables from `server/src/aweb/migrations/aweb/001_initial.sql`
  plus split notes where one table contains mixed core/domain columns.
  The post-m3 app-platform tables from `008_app_registry_grants.sql` and
  `009_app_events.sql` are not extraction candidates and are excluded from the
  shrink score.
- **API routers/routes** are FastAPI routers included by `server/src/aweb/api.py`.
  Route counts count concrete `@router.<method>` declarations in the referenced
  router file. Shared/split routers are called out separately so a later
  extraction can remove only the domain-specific reads while leaving core
  presence/control intact.
- **MCP tools** are the 43 static registrations in `server/src/aweb/mcp/server.py`
  (32 canonical + 11 legacy aliases). Counts separate canonical tools from
  legacy compatibility aliases.
- **Rough LOC** is production server + Go CLI code only, excluding blank lines
  and line comments. It is intentionally rough: enough to detect whether a
  milestone truly shrinks core. Tests are excluded.

## Grand-total shrink baseline

| Surface | SOT/core total | Extraction-candidate baseline |
|---|---:|---:|
| Full DB tables | 26 | 15 full tables + split `workspaces` columns |
| Primary API routers | 18 | 7 routers (`tasks`, `claims`, `reservations`, `repos`, `chat`, `messages`, `conversations`) |
| Primary API routes | n/a | 34 routes |
| Shared/split API routers touching candidates | 18 | 3 routers (`workspaces`, `status`, `dashboard`) / 12 candidate-sensitive routes |
| Canonical MCP tools | 32 | 20 direct (`tasks/work` 13 + `messages/chat` 7) + 1 split (`workspace_status`) |
| Legacy MCP aliases touching candidates | 11 | 7 messaging aliases |
| Rough production LOC, direct candidate files | n/a | 14,406 LOC |
| Rough production LOC, shared/split files | n/a | 4,288 LOC |
| Rough production LOC, candidate-sensitive total | n/a | 18,694 LOC |

Notes:

- The 15 full candidate tables are 6 task tables + 1 lock table + 1 repo table +
  7 messaging/chat tables.
- `workspaces` is a split table: core keeps identity/location/role/last_seen;
  `focus_task_ref` / `focus_updated_at` move to tasks/dev per SOT §5.
- Shared/split LOC is not assigned to one domain because the same files expose
  mixed core, tasks, locks, and repo status. Extraction milestones should reduce
  the relevant domain branches in these files without deleting core presence.

## Domain scorecards

### 1. Tasks / work / claims

| Surface | Current core occupancy | File refs |
|---|---:|---|
| DB tables | 6 full tables + split `workspaces` focus columns | `001_initial.sql`: `tasks`, `task_comments`, `task_dependencies`, `task_counters`, `task_root_counters`, `task_claims`, `workspaces.focus_task_ref`, `workspaces.focus_updated_at` |
| Primary API routers/routes | 2 routers / 13 routes | `coordination/routes/tasks.py` = 12 routes; `routes/claims.py` = 1 route |
| Shared/split API routes | `workspaces` 6 routes, `status` 2 routes, dashboard `claims`/`tasks`/`status` reads | `coordination/routes/workspaces.py`; `routes/status.py`; `routes/dashboard.py` |
| MCP tools | 13 canonical direct + 1 split | `task_create`, `task_list`, `task_ready`, `task_get`, `task_close`, `task_update`, `task_reopen`, `task_claim`, `task_comment_add`, `task_comment_list`, `work_ready`, `work_active`, `work_blocked`; split `workspace_status` |
| Go CLI surface | `aw task` command group + `aw work` command group; workspace/status commands read task claims/focus | `cli/go/cmd/aw/task*.go`; `cli/go/cmd/aw/work.go`; split `workspace.go`, `doctor_aweb.go` |
| Rough direct LOC | 2,980 | Server 1,931 + CLI 1,049 |

Primary route inventory:

- `coordination/routes/tasks.py`: `POST /v1/tasks`, `GET /v1/tasks`,
  `GET /v1/tasks/ready`, `GET /v1/tasks/blocked`, `GET /v1/tasks/active`,
  `GET/PATCH/DELETE /v1/tasks/{ref}`, dependency add/remove, comment add/list.
- `routes/claims.py`: `GET /v1/claims`.

Direct LOC refs:

- Server: `coordination/routes/tasks.py`, `routes/claims.py`, `claims.py`,
  `coordination/tasks_service.py`, `mcp/tools/tasks.py`, `mcp/tools/work.py`.
- CLI: `task.go`, `task_create.go`, `task_list.go`, `task_show.go`,
  `task_update.go`, `task_close.go`, `task_reopen.go`, `task_delete.go`,
  `task_dep.go`, `task_comment.go`, `task_stats.go`, `work.go`.

### 2. Locks / reservations

| Surface | Current core occupancy | File refs |
|---|---:|---|
| DB tables | 1 full table | `001_initial.sql`: `reservations` |
| Primary API routers/routes | 1 router / 5 routes | `routes/reservations.py`: list/acquire/renew/release/revoke |
| Shared/split API routes | `status` reports `locks`; dashboard status includes `active_locks` | `routes/status.py`; `routes/dashboard.py`; SOT §5 lock deprecation surface |
| MCP tools | 0 | No `@mcp.tool` registration for locks |
| Go CLI surface | `aw lock` command group with 5 subcommands | `cli/go/cmd/aw/lock.go` (`acquire`, `renew`, `release`, `revoke`, `list`) |
| Rough direct LOC | 540 | Server 364 + CLI 176 |

Primary route inventory:

- `routes/reservations.py`: `GET /v1/reservations`, `POST /v1/reservations`,
  `POST /v1/reservations/renew`, `POST /v1/reservations/release`,
  `POST /v1/reservations/revoke`.

Direct LOC refs:

- Server: `routes/reservations.py`, `routes/_reservation_utils.py`.
- CLI: `lock.go`.

### 3. Repos / git metadata

| Surface | Current core occupancy | File refs |
|---|---:|---|
| DB tables | 1 full table + workspace FK/reference usage | `001_initial.sql`: `repos`; `workspaces.repo_id` |
| Primary API routers/routes | 1 router / 4 routes | `coordination/routes/repos.py`: lookup/ensure/list/delete |
| Shared/split API routes | `connect` can ensure repo from `repo_origin`; `status`, `agents`, `workspaces` join/read repo metadata | `routes/connect.py`; `routes/status.py`; `routes/agents.py`; `coordination/routes/workspaces.py`; `presence.py` Redis repo indexes |
| MCP tools | 0 direct | Repo context appears through split `workspace_status`, not a repo MCP tool |
| Go CLI surface | No top-level `aw repo` command; repo origin is detected/sent by init/connect/workspace flows | `cli/go/cmd/aw/init_connect.go`; `workspace.go`; `doctor_local.go`; `git_runtime_state.go` |
| Rough direct LOC | 340 | Server 340 + CLI 0 direct |

Primary route inventory:

- `coordination/routes/repos.py`: `POST /v1/repos/lookup`,
  `POST /v1/repos/ensure`, `GET /v1/repos`, `DELETE /v1/repos/{repo_id}`.

Direct LOC refs:

- Server: `coordination/routes/repos.py`.
- CLI: no direct repo command counted; repo metadata is embedded in split
  workspace/init/status flows.

### 4. Messaging / messages / chat

| Surface | Current core occupancy | File refs |
|---|---:|---|
| DB tables | 7 full tables | `001_initial.sql`: `conversations`, `conversation_participants`, `messages`, `chat_sessions`, `chat_participants`, `chat_messages`, `chat_read_receipts` |
| Primary API routers/routes | 3 routers / 12 routes | `routes/messages.py` = 4; `routes/chat.py` = 7; `routes/conversations.py` = 1 |
| Shared/split API routes | Dashboard `messages` read; event/status wake paths observe mail/chat | `routes/dashboard.py`; `routes/events.py`; `messaging/waiting.py` |
| MCP tools | 7 canonical direct + 7 legacy aliases | Canonical: `send_mail`, `check_mail`, `send_chat`, `check_chats`, `read_chat`, `mark_chat_read`, `read_contact_messages`; legacy: `check_inbox`, `chat_send`, `chat_pending`, `chat_history`, `chat_read`, `send_message_to_contact`, `read_messages_from_contact` |
| Go CLI surface | `aw mail`, `aw chat`, notification/log helpers | `cli/go/cmd/aw/mail.go`; `chat.go`; `notify.go`; `commlog.go`; `doctor_messaging.go` |
| Rough direct LOC | 10,546 | Server 8,660 + CLI 1,886 |

Primary route inventory:

- `routes/messages.py`: `GET /v1/messages/conversations/{conversation_id}`,
  `POST /v1/messages`, `GET /v1/messages/inbox`,
  `POST /v1/messages/{message_id}/ack`.
- `routes/chat.py`: create/list/pending/history/read/stream/send under
  `/v1/chat/sessions`.
- `routes/conversations.py`: `GET /v1/conversations`.

Direct LOC refs:

- Server: `routes/messages.py`, `routes/chat.py`, `routes/conversations.py`,
  `messaging/messages.py`, `messaging/chat.py`, `messaging/conversations.py`,
  `messaging/mail_routing.py`, `e2ee_messages.py`, `mcp/tools/mail.py`,
  `mcp/tools/chat.py`.
- CLI: `mail.go`, `chat.go`, `notify.go`, `commlog.go`, `doctor_messaging.go`.

## Shared/split surface refs

These files are not assigned wholly to one extraction domain, but they are where
core shrink must be visible after domain extraction:

| Shared file set | Candidate data currently exposed | Rough LOC |
|---|---|---:|
| `coordination/routes/workspaces.py`, `coordination/workspace_registry.py` | task claims aggregation, focus task, repo fields | 1,150 server LOC |
| `routes/status.py` | task claims/conflicts, locks, focus task, repo filters/joins | 588 server LOC |
| `routes/dashboard.py` | dashboard reads for claims, tasks, messages, active locks/status | 609 server LOC |
| `mcp/tools/workspace.py` | `workspace_status` includes claims/work context | 129 server LOC |
| `workspace.go`, `heartbeat.go`, `doctor_aweb.go` | CLI status/workspace/doctor composition of claims, locks, repo | 1,812 CLI LOC |

Shared/split subtotal: 4,288 rough LOC.

## Baseline checks for future extraction DoD

A future extraction milestone should report at least:

1. Which rows above shrink and by how much (tables, primary routes, MCP tools,
   CLI command surface, rough LOC).
2. Which shared/split files still contain compatibility glue and when that glue
   expires.
3. Whether static MCP registrations were removed or replaced by app-manifest
   composition.
4. Whether CLI compatibility remains as an alias/proxy and whether it is counted
   as retained core weight.
5. A post-extraction scorecard delta against this file.
