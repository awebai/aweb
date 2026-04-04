# Configuration

This guide covers the local files that make `aw` work in a repo or worktree.

## Global Config: `~/.config/aw/config.yaml`

The global config stores saved servers, accounts, and defaults.

Default path:

```text
~/.config/aw/config.yaml
```

Override it with:

```bash
export AW_CONFIG_PATH=/path/to/config.yaml
```

Typical contents include:

- `servers`
- `accounts`
- `default_account`
- `client_default_accounts`

The keys directory lives alongside this file under `keys/`.

## Worktree Signing Key: `.aw/signing.key`

Self-custodial workspace identities store their active private signing key in:

```text
.aw/signing.key
```

The global config points at this file, but the key material itself is
worktree-local.

## Workspace Binding: `.aw/workspace.yaml`

`.aw/workspace.yaml` is the repo/worktree-local binding file. It stores the
local project binding and coordination state together, including fields such as:

- `server_url`
- `api_key`
- `project_id`
- `project_slug`
- `namespace_slug`
- `identity_id`
- `identity_handle`
- `did`
- `stable_id`
- `signing_key`
- `custody`
- `lifetime`
- `workspace_id`
- `repo_id`
- `canonical_origin`
- `role_name`

This file is what makes worktree-aware commands like `aw workspace status`,
`aw workspace add-worktree`, and `aw run` coordination-aware, and it is also
the first local source of truth for binding a directory to a project identity.

## Local Context: `.aw/context`

`.aw/context` is a non-secret pointer from the current directory to a saved
account name.

Bootstrap commands such as `aw project create`, `aw init`,
`aw spawn accept-invite`, and `aw connect` write it by default unless you pass
`--write-context=false`.

This file remains useful for selecting among saved global accounts, but it is no
longer the complete local binding by itself.

## Resolution Order

When more than one config source is present, the effective selection order is:

1. CLI flags such as `--server-name` and `--account`
2. environment variables
3. local `.aw/workspace.yaml`
4. local `.aw/context`
5. global defaults in `config.yaml`

That means a directory-local `.aw/workspace.yaml` can fully bind one repo or
worktree, while `.aw/context` still guides account-name selection when needed.

## Injected Coordination Docs

Several bootstrap commands can inject coordination instructions into local
agent-facing docs:

- `aw project create --inject-docs`
- `aw init --inject-docs`
- `aw spawn accept-invite --inject-docs`

The injector targets:

- `CLAUDE.md`
- `AGENTS.md`

If neither file exists, it creates `AGENTS.md`.

The injected block includes the default coordination starter commands:

```bash
aw roles show
aw workspace status
aw work ready
aw mail inbox
```

## Related Runtime Config

`aw run --init` writes a separate runtime config file:

```text
~/.config/aw/run.json
```

Use that file for `aw run` prompt defaults and background service settings.
