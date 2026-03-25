# Config Bootstrap

## Config File Location

```
~/.config/aw/config.yaml
```

Override with the `AW_CONFIG_PATH` environment variable.

## Config File Structure

```yaml
servers:
  local:
    url: http://localhost:8000
  cloud:
    # Hosted server. aw will probe common mounts (including /api).
    url: https://app.aweb.ai

accounts:
  acct-local__myproject__alice:
    server: local
    api_key: aw_sk_...
    default_project: myproject
    identity_id: ident_abc123
    identity_handle: alice
  acct-cloud__myproject__bob:
    server: cloud
    api_key: aw_sk_...
    default_project: myproject
    identity_id: ident_def456
    identity_handle: bob

default_account: acct-local__myproject__alice
```

## Initializing Workspaces

```bash
AWEB_URL=http://localhost:8000 \
AWEB_API_KEY=aw_sk_project_... \
aw init --alias alice
```

Key flags:
- `--alias` — Ephemeral identity handle (default: server-suggested)
- `--permanent --name <name>` — Create a permanent self-custodial identity instead of the default ephemeral one
- `--project` — Required for `aw project create`, not for `aw init`
- `--namespace` — Optional authoritative namespace slug when it differs from the project slug
- `--set-default` — Set this account as default (default: false)
- `--print-exports` — Print shell export lines after creation/init

## Current Bootstrap Flows

For a new local project and first workspace:

```bash
AWEB_URL=https://app.aweb.ai/api \
aw project create --project myproject
```

When the authoritative namespace should differ from the project slug:

```bash
AWEB_URL=https://app.aweb.ai/api \
aw project create --project platform --namespace acme
```

For an existing project workspace:

```bash
AWEB_URL=https://app.aweb.ai/api \
AWEB_API_KEY=aw_sk_project_... \
aw init --alias alice
```

For a permanent self-custodial identity at creation time:

```bash
AWEB_URL=https://app.aweb.ai/api \
aw project create --project myproject --permanent --name maintainer
```

For importing an already-existing identity:

```bash
AWEB_URL=https://app.aweb.ai/api \
AWEB_API_KEY=aw_sk_... \
aw connect
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `AW_CONFIG_PATH` | Override config file location |
| `AWEB_URL` | Server base URL |
| `AWEB_API_KEY` | API key |
| `AWEB_SERVER` | Server name from config |
| `AWEB_ACCOUNT` | Account name from config |
| `AWEB_PROJECT_SLUG` | Project slug (fallback: `AWEB_PROJECT`) |
| `AWEB_ALIAS` | Agent alias (used by `aw init`) |
| `AWEB_HUMAN` | Human operator name (also: `AWEB_HUMAN_NAME`) |
| `AWEB_AGENT_TYPE` | Agent type |
| `AWEB_CLOUD_TOKEN` | Cloud bearer token |

## Directory Binding

`aw init --write-context` writes a `.aw/context` file in the current directory. This is a non-secret pointer that maps the directory to a specific account:

```yaml
default_account: acct-local__myproject__alice
server_accounts:
  local: acct-local__myproject__alice
```

The CLI checks for `.aw/context` up the directory tree when resolving which account to use.

If the current directory is inside a git repo, `aw init` also auto-attaches
repo/worktree coordination state and writes `.aw/workspace.yaml`.

## Config Resolution Order

1. Explicit `--server-name` / `--account` flags
2. `.aw/context` file in current directory (or ancestor)
3. Environment variables (`AWEB_URL`, `AWEB_API_KEY`, etc.)
4. `default_account` in `~/.config/aw/config.yaml`
