# OSS aweb server inventory — tables, MCP tools, routers (SOT §4 backing)

Reference artifact for the restructuring SOT (`../restructuring-sot.md` §4–§5).
Grounded in `aweb/server/src/aweb/` as of 2026-06-15. Target column uses the
SOT's classification: **core** (authority/addressability/control) /
**core-transport** / **messages/chat app** (bundled, stays in core during
transition) / **tasks app** / **dev** / **control-plane** / **drop**.

## 1. Tables — 26 (migration `migrations/aweb/`, 001 + 002–007)

| Table | Target | Note |
|---|---|---|
| teams | core | team identity / controller binding |
| agents | core | agent identity registry |
| agent_encryption_keys | core | E2EE key assertions (`assertion_custody` self/hosted_custodial; 002 & 007) |
| contacts | core | address book (addressability) |
| control_signals | core | pause/resume/interrupt control channel |
| team_roles | core | runtime team facts (read at boot) |
| team_instructions | core | runtime team facts (read at boot) |
| federated_message_deliveries | core-transport | inbound federation idempotency |
| conversations | messages/chat app | (stays in core during transition) |
| conversation_participants | messages/chat app | |
| messages | messages/chat app | encrypted_v2 cols added 003 |
| chat_sessions | messages/chat app | |
| chat_participants | messages/chat app | added 006 |
| chat_messages | messages/chat app | encrypted_v2 cols added 004 |
| chat_read_receipts | messages/chat app | |
| tasks | tasks app | |
| task_comments | tasks app | |
| task_dependencies | tasks app | |
| task_counters | tasks app | |
| task_root_counters | tasks app | |
| task_claims | tasks app | |
| reservations | drop-or-dev | locks; isolated, no MCP tool |
| repos | dev | git-specific (origin_url/canonical_origin) |
| workspaces | split | core: identity/location/role/last_seen; tasks/dev: focus_task_ref/focus_updated_at |
| audit_log | control-plane / observability | mutation audit |

## 2. MCP tools — 43 (`mcp/server.py`; 32 canonical + 11 legacy aliases)

Verified: `@mcp.tool(` registrations count = 43.

### Canonical (32)
- **core / gateway-provided (11):** whoami; list_agents; heartbeat;
  list_contacts; add_contact; add_contact_by_handle; remove_contact;
  roles_show; roles_list; instructions_show; instructions_history.
- **→ messages/chat app (7):** send_mail; check_mail; send_chat; check_chats;
  read_chat; mark_chat_read; read_contact_messages.
- **→ tasks app (13):** task_create; task_list; task_ready; task_get;
  task_close; task_update; task_reopen; task_claim; task_comment_add;
  task_comment_list; work_ready; work_active; work_blocked.
- **split (1):** workspace_status (presence part core, claims part → tasks/dev).

Canonical total = 11 + 7 + 13 + 1 = 32. With 11 legacy aliases = 43.

### Legacy aliases (11) — keep behind a deprecation window, remove post-migration
check_inbox, chat_send, chat_pending, chat_history, chat_read, contacts_list,
contacts_add, contacts_remove, add_contact_by_email, send_message_to_contact,
read_messages_from_contact.

> Under the SOT the MCP surface is **composed dynamically from app manifests**
> (§6.5/§7); this static list is the current state and the migration source, not
> the target. messages/task tools become app-manifest-contributed.

## 3. Routers `api.py` includes — 18

### `routes/` (13)
agents (core) · connect (core) · contacts (core) · events (core event channel) ·
federation (→ core-transport: becomes the signed-envelope transport) ·
conversations (messages/chat app) · chat (messages/chat app) · messages
(messages/chat app) · claims (tasks app) · reservations (drop-or-dev) · status
(split) · dashboard (dev/visibility) · service_registration (drop / fold to
control-plane).

### `coordination/routes/` (5) — *missing from the first SOT draft*
team_instructions (core) · team_roles (core) · repos (**dev**, git-specific —
not silently core) · tasks (tasks app) · workspaces (split).

## 4. Status / workspace read surface (SOT §5 split evidence)

| Read | task_claims | reservations | focus_task_ref | repos |
|---|---|---|---|---|
| `GET /v1/status` (routes/status.py) | ✓ | ✓ (`locks`) | ✓ | ✓ |
| MCP `workspace_status` (mcp/tools/workspace.py) | ✓ | ✗ | ✗ | ✗ |
| `GET /v1/workspaces/team` (coordination/routes/workspaces.py) | ✓ (agg) | ✗ | ✓ | ✓ |

Target split: **core presence read** = identity / workspace / presence / role /
last_seen only; **tasks/dev augmented read** = claims / focus / locks / repo.
CLI composes both during transition.

## 5. Locks deprecation surface (SOT §5)
`aw lock` (CLI, `cli/go/reservations.go`); `GET /v1/status` `locks` array;
dashboard `active_locks` (`routes/dashboard.py`); `aw doctor` (CLI-side, parses
status). No MCP tool. → drop-or-dev **with** an explicit CLI/API deprecation +
compat path or it breaks dogfooding.
