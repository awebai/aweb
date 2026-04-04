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

## Directory Binding: `.aw/context`

`.aw/context` is a non-secret pointer from the current directory to a saved
account.

Bootstrap commands such as `aw project create`, `aw init`,
`aw spawn accept-invite`, and `aw connect` write it by default unless you pass
`--write-context=false`.

This is how `aw` knows which account to use when you enter a repo.

## Worktree Coordination State: `.aw/workspace.yaml`

`.aw/workspace.yaml` is the repo/worktree-local coordination identity file. It
stores workspace metadata such as:

- `workspace_id`
- `project_id`
- `project_slug`
- `repo_id`
- `canonical_origin`
- `alias`
- `human_name`
- `role_name`
- `hostname`
- `workspace_path`

This file is what makes worktree-aware commands like `aw workspace status`,
`aw workspace add-worktree`, and `aw run` coordination-aware.

## Resolution Order

When more than one config source is present, the effective selection order is:

1. CLI flags such as `--server-name` and `--account`
2. environment variables
3. local `.aw/context`
4. global defaults in `config.yaml`

That means a directory-local `.aw/context` can intentionally override your
global default account for one repo.

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
