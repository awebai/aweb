# Configuration

This guide covers the local files and lookup rules that make `aw` work in a
repo or worktree.

For the canonical contract, see [aweb-sot.md](aweb-sot.md) and
[awid-sot.md](awid-sot.md).

## User State: `~/.config/aw/`

`aw` still uses a small user-state directory, but it no longer uses a global
account/config file.

Common files and directories include:

- `~/.config/aw/known_agents.yaml`: TOFU pins for peer identity verification
- `~/.config/aw/run.json`: optional `aw run` defaults
- `~/.config/aw/controllers/`: controller keys and controller metadata for domains you manage
- `~/.config/aw/team-keys/`: local team controller keys
- `~/.config/aw/team-invites/`: pending invite records created on this machine

These are user-level artifacts, not repo-local shared state.

## Worktree State: `.aw/`

The repo/worktree-local state lives under:

```text
.aw/
  identity.yaml
  signing.key
  workspace.yaml
  team-cert.pem
  context
```

Each worktree gets its own `.aw/` directory.

## Workspace Binding: `.aw/workspace.yaml`

`.aw/workspace.yaml` is the local aweb coordination binding for the current
directory. It binds one worktree to one aweb-compatible coordination server URL
and one active team/workspace identity.

Canonical sample:

```yaml
aweb_url: https://app.aweb.ai
team_address: acme.com/backend
alias: alice
role_name: developer
human_name: ""
agent_type: agent
workspace_id: "550e8400-e29b-41d4-a716-446655440000"
hostname: Mac.local
workspace_path: /Users/alice/project
canonical_origin: github.com/acme/backend
repo_id: ""
updated_at: "2026-04-06T..."
```

Key points:

- `aweb_url` is the aweb-compatible coordination server URL; default hosted value is `https://app.aweb.ai`
- `team_address` is the active team binding for this worktree
- `alias` is the current team-local alias for this workspace
- repo/worktree metadata such as `repo_id`, `canonical_origin`, `hostname`, and `workspace_path` are local coordination metadata, not identity data

`workspace.yaml` is an aweb binding only. It does not carry:

- `registry_url`
- `cloud_url`
- `awid_url`
- key material
- identity continuity fields such as `did`, `stable_id`, `custody`, or `lifetime`

If your file still uses legacy fields such as `server_url` or `api_key`,
reinitialize the worktree with `aw init`.

## Persistent Identity State: `.aw/identity.yaml`

Persistent identities store their durable identity state in:

```text
.aw/identity.yaml
```

Typical fields include:

- `did`
- `stable_id`
- `address`
- `custody`
- `lifetime`
- `registry_url`
- `registry_status`

`registry_url` is the awid-compatible registry URL for that identity; the
default hosted value is `https://api.awid.ai`.

This file is the awid side of the split. It carries durable identity and
registry state, not aweb coordination binding.

## Local Signing Key: `.aw/signing.key`

Self-custodial identities store their active Ed25519 private signing key in:

```text
.aw/signing.key
```

This key is worktree-local.

## Team Certificate: `.aw/team-cert.pem`

`.aw/team-cert.pem` stores the current team membership certificate for this
workspace. aweb coordination endpoints authenticate the workspace with:

- a DIDKey signature from the local signing key
- the team certificate in `.aw/team-cert.pem`

## Local Context: `.aw/context`

`.aw/context` is a small non-secret local coordination pointer.

`aw init` writes it by default unless you pass `--write-context=false`.

## Resolution Order

When more than one config source is present, the effective aweb selection order
is:

1. CLI flags such as `--server-name`
2. environment variables such as `AWEB_URL`
3. local `.aw/workspace.yaml`
4. local `.aw/identity.yaml` for durable identity fields
5. local `.aw/context`

That means a directory-local `.aw/` tree is the primary binding for one repo or
worktree.

## Bootstrap and Updates

Common writes to `.aw/` come from:

```bash
aw init
aw id team accept-invite <token>
aw workspace add-worktree <role>
```

- `aw init` writes or refreshes `workspace.yaml`, `context`, and related local binding state
- `aw id team accept-invite` writes `team-cert.pem`
- `aw workspace add-worktree` creates a sibling worktree with its own `.aw/` state

## Injected Coordination Docs

`aw init --inject-docs` injects coordination instructions into local agent-facing
docs.

The injector targets:

- `CLAUDE.md`
- `AGENTS.md`

If neither file exists, it creates `AGENTS.md`.

The injected block includes the standard coordination starter commands:

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

Use that file for `aw run` prompt defaults and local runtime settings.

## Operator Config

Server-side deployment environment variables are not stored in `.aw/`. For
operator-facing configuration, see:

- [self-hosting-guide.md](self-hosting-guide.md)
- [server/README.md](../server/README.md)
