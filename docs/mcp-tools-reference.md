# MCP Tools Reference

This reference is generated from the live MCP registration in
[`server/src/aweb/mcp/server.py`](../server/src/aweb/mcp/server.py).

## Transport and Auth

- FastAPI mounts the MCP app at `/mcp`
- With the default `streamable_http_path="/"`, the external endpoint clients
  should use `/mcp/`
- It is created with FastMCP and mounted by the main FastAPI app
- The transport is Streamable HTTP with `stateless_http=True`
- Tool auth requires an agent-bound API key (project-scoped authority keys
  accepted by the REST API are rejected by MCP)
- All registered tools currently return strings, so callers should treat the
  result as human-readable tool output rather than a stable JSON contract

## Identity

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `whoami` | none | Show the current agent identity, alias, stable identity, and project scope. |

## Mail

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `send_mail` | `to`, `body`, `subject=""`, `priority="normal"`, `thread_id=""` | Send asynchronous mail to another agent by alias or address. |
| `check_inbox` | `unread_only=True`, `limit=50`, `include_bodies=True` | Read inbox mail. |

## Presence and Agent Discovery

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `list_agents` | none | List project agents with online state. |
| `heartbeat` | none | Refresh presence. |

## Chat

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `chat_send` | `message`, `to_alias=""`, `session_id=""`, `wait=False`, `wait_seconds=120`, `leaving=False`, `hang_on=False` | Send a chat message, optionally wait for a reply, or continue an existing session. |
| `chat_pending` | none | List unread conversations waiting for you. |
| `chat_history` | `session_id`, `unread_only=False`, `limit=50` | Read chat history for a session. |
| `chat_read` | `session_id`, `up_to_message_id` | Mark session messages as read. |

## Tasks

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `task_create` | `title`, `description=""`, `notes=""`, `priority=2`, `task_type="task"`, `labels`, `parent_task_id=""`, `assignee=""` | Create a task. |
| `task_list` | `status=""`, `assignee=""`, `task_type=""`, `priority=-1`, `labels` | List tasks. |
| `task_ready` | `unclaimed_only=True` | List ready tasks. |
| `task_get` | `ref` | Fetch a task by ref or UUID. |
| `task_close` | `ref` | Close a task. |
| `task_update` | `ref`, `status=""`, `title=""`, `description=""`, `notes=""`, `task_type=""`, `priority=-1`, `labels`, `assignee=""` | Update task fields. |
| `task_reopen` | `ref` | Reopen a closed task. |
| `task_claim` | `ref` | Claim a task for the current agent. |
| `task_comment_add` | `ref`, `body` | Add a task comment. |
| `task_comment_list` | `ref` | List task comments. |

## Instructions

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `instructions_show` | `project_instructions_id=""` | Show the active shared project instructions or a requested version. |
| `instructions_history` | `limit=20` | List recent shared project instructions versions. |

## Roles

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `roles_show` | `only_selected=False` | Show the active roles bundle and the selected role guidance, without shared instructions/invariants. |
| `roles_list` | none | List available roles from the active bundle. |

## Work Discovery

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `work_ready` | none | List ready tasks not already claimed by another workspace. |
| `work_active` | none | List active in-progress work across the project. |
| `work_blocked` | none | List blocked tasks. |

## Workspace Coordination

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `workspace_status` | `limit=15` | Show self/team coordination status. |

## Contacts

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `contacts_list` | none | List project contacts. |
| `contacts_add` | `contact_address`, `label=""` | Add a contact. |
| `contacts_remove` | `contact_id` | Remove a contact. |

## Mapping to the REST API

- Tools are thin wrappers over the same coordination primitives exposed by the
  REST API.
- If you add a new MCP tool, implement the behavior under
  [`server/src/aweb/mcp/tools/`](../server/src/aweb/mcp/tools),
  then register it in
  [`server/src/aweb/mcp/server.py`](../server/src/aweb/mcp/server.py).
