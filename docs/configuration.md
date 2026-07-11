---
title: "Configuration"
kicker: "Reference"
description: "Local files and lookup rules that make aw work in a repo or worktree."
weight: 100
---

# Configuration

This guide covers the local files and lookup rules that make `aw` work in a
repo or worktree.

For the canonical contract, see [aweb-sot.md](aweb-sot.md) and
[awid-sot.md](awid-sot.md).

## AWID Controller State: `~/.awid/`

AWID namespace and team controller private keys are user-level authority keys.
Keep `~/.awid` safe and backed up. Losing these keys can leave you unable to
manage namespace addresses or team membership without a DNS recovery flow.

Common files and directories include:

- `~/.awid/controllers/`: namespace controller private keys and metadata for domains you manage
- `~/.awid/team-keys/`: team controller private keys for local-controller teams

## User State: `~/.config/aw/`

`aw` still uses a small user-state directory, but it no longer uses a global
account/config file.

Common files and directories include:

- `~/.config/aw/known_agents.yaml`: TOFU pins for peer identity verification
- `~/.config/aw/run.json`: optional `aw run` defaults
- `~/.config/aw/team-invites/`: pending local-controller invite records created on this machine

These are user-level artifacts, not repo-local shared state.

## Worktree State: `.aw/`

The repo/worktree-local state lives under:

```text
.aw/
  identity.yaml
  signing.key
  workspace.yaml
  team-certs/
  context
```

Each worktree gets its own `.aw/` directory.

## Workspace Binding: `.aw/workspace.yaml`

`.aw/workspace.yaml` is the local aweb coordination binding for the current
directory. It binds one worktree to one aweb-compatible coordination server URL
and one active team/workspace identity while retaining the other team
memberships held by the same local identity.

Canonical sample:

```yaml
aweb_url: https://app.aweb.ai
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    role_name: developer
    workspace_id: "550e8400-e29b-41d4-a716-446655440000"
    cert_path: team-certs/backend__acme.com.pem
    joined_at: "2026-04-06T..."
human_name: ""
agent_type: agent
hostname: Mac.local
workspace_path: /Users/alice/project
canonical_origin: github.com/acme/backend
repo_id: ""
updated_at: "2026-04-06T..."
```

Key points:

- `aweb_url` is the aweb-compatible coordination server URL; default hosted value is `https://app.aweb.ai`
- `active_team` points to the membership the CLI uses by default
- `memberships` holds the per-team alias/workspace/certificate state for this one identity
- repo/worktree metadata such as `repo_id`, `canonical_origin`, `hostname`, and `workspace_path` are local coordination metadata, not identity data

Multi-team commands:

- `aw id team accept-invite --global <invite-token>` (or `aw team join --global <invite-token>`) adds another team membership to the same global identity; the old `aw id team add <invite-token>` form is deprecated
- `aw id team switch <team_id>` changes `active_team`
- `aw id team list` shows all local memberships for the current worktree
- `aw id team leave <team_id>` removes one local membership and its certificate from this worktree only
- relevant coordination commands accept `--team <team_id>` to use a non-active membership for that one command

`workspace.yaml` is an aweb binding only. It does not carry:

- `registry_url`
- registry-specific URL fields
- hosted-bootstrap URL fields
- key material
- identity continuity fields such as `did`, `stable_id`, `custody`, or
  canonical `identity_scope`

If your file still uses removed legacy bootstrap/auth fields,
reinitialize the worktree with `aw init`.

## Global Identity State: `.aw/identity.yaml`

Global identities store their durable identity state in:

```text
.aw/identity.yaml
```

Current schema version: `2`.

Typical fields include:

- `schema_version: 2`
- `did`
- `stable_id`
- `address`
- `custody`
- `identity_scope`
- `registry_url`
- `registry_status`

`registry_url` is the awid-compatible registry URL for that identity; the
default hosted value is `https://api.awid.ai`.

This file is the awid side of the split. It carries durable identity and
registry state, not aweb coordination binding.

Compatibility note: older `.aw/identity.yaml` files may still store the
identity class in a `lifetime` field with `persistent`/`ephemeral` values. New
writes use `schema_version: 2` and `identity_scope=global|local`; they do not
write `lifetime`. The old `lifetime` field is deprecated-read-compat only until
the cleanup window removes or fully quarantines it.

## Local Signing Key: `.aw/signing.key`

Self-custodial identities store their active Ed25519 private signing key in:

```text
.aw/signing.key
```

## Local E2E Encryption Keyring: `.aw/encryption.yaml`

Self-custodial E2E messaging uses a separate X25519 encryption keyring:

```text
.aw/encryption.yaml
.aw/encryption-keys/
```

`encryption.yaml` records the active encryption key id. `encryption-keys/`
contains the active private encryption key, archived private encryption keys
needed for old messages, and the identity-signed public assertions that can be
published to AWID or an aweb service. New self-custodial identity and
membership paths create the local key automatically. These keys are not app
configuration and are never uploaded to AC/aweb.

Repair or publish the active key with:

```bash
aw id encryption-key setup
```

Rotate with:

```bash
aw id encryption-key rotate
```

Back up `.aw/encryption-keys/` with the workspace. Losing an archived
encryption private key makes messages encrypted to that key unrecoverable; the
server cannot repair or decrypt them.

This key is worktree-local.

## Team Certificates: `.aw/team-certs/`

`.aw/team-certs/` stores one team membership certificate per team for this
workspace identity. aweb coordination endpoints authenticate the workspace with:

- a DIDKey signature from the local signing key
- the active team certificate referenced from `.aw/workspace.yaml`

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
- `aw id team accept-invite` writes a team certificate under `team-certs/`; local accepts create/reuse local key material for one team, while `--global` reuses an existing self-custodial global identity from `identity.yaml` rather than minting a new `did:aw`
- `aw workspace add-worktree` creates a sibling worktree with its own `.aw/` state

## Injected Coordination Docs

`aw init` injects coordination instructions into local agent-facing
docs by default. Use `aw init --do-not-touch-agents-md` to skip
this file update.

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

## Network Timeouts and Hostile Venue WiFi

Normal `aw` API requests use a 30s timeout by default. Override it with
`AWEB_HTTP_TIMEOUT` (Go duration syntax):

```bash
AWEB_HTTP_TIMEOUT=45s aw work ready
```

On conference or venue WiFi (NAT pressure, captive portals, silent
blackholing), raise `AWEB_HTTP_TIMEOUT` above the 30s default and retry reads
freely. For a timed-out write (task create/update, mail send), the request may
have reached the server before the response was lost: check current state with
the matching read command before retrying, instead of resending blindly.

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
