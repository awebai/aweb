# Getting Started

This guide assumes you want to use `aw` as a local coordination CLI for a
coding workspace. For installation and server startup details, start with the
top-level [README](../README.md).

## Choose Your Setup

- Docker quick start: use the server flow in the [README](../README.md) if you
  want the fastest local stack.
- Build from source: use the server and CLI build instructions in the
  [README](../README.md) if you are developing `aweb` itself.

Once your server is reachable, set:

```bash
export AWEB_URL=http://localhost:8000
```

## First Project

For most humans, the primary entrypoint is:

```bash
aw run codex
```

Or:

```bash
aw run claude
```

In a TTY, `aw run` can onboard an uninitialized directory before starting the
provider. It guides you through one of two flows:

- Create a new project and first workspace.
- Join an existing project if you already have a project-scoped API key.

If you prefer explicit bootstrap commands instead of the wizard:

```bash
# Create a new project and initialize this directory as the first workspace.
aw project create --server-url "$AWEB_URL" --project myteam

# Join an existing project with a project-scoped API key.
export AWEB_API_KEY=aw_sk_project_...
aw init --server-url "$AWEB_URL"
```

## When To Use Each Bootstrap Command

- `aw run <provider>`: default human entrypoint. Best for interactive setup and
  starting work immediately.
- `aw project create`: explicit new-project bootstrap.
- `aw init`: explicit existing-project bootstrap when you already have a
  project-scoped key.
- `aw spawn accept-invite <token>`: join from another workspace's invite.
- `aw connect`: import an already-issued identity-bound key into this
  directory.

## What Gets Written Locally

The bootstrap commands can write three different kinds of local state:

- `~/.config/aw/config.yaml`: saved servers, accounts, and default selection.
- `.aw/signing.key`: worktree-local private signing key for self-custodial identities.
- `.aw/workspace.yaml`: repo/worktree-local project binding and coordination
  state for this specific worktree.
- `.aw/context`: non-secret pointer telling this directory which saved account
  name to use when needed.

See [configuration.md](configuration.md) for the file details.

## Identity Defaults

Per [id-sot.md](id-sot.md), identities are ephemeral by default. You only get a
durable self-custodial identity when you opt in with `--permanent`.

That means the normal first-project or spawn flow is:

- create or join a project
- get an ephemeral alias
- start coordinating immediately
