# aw Identity System

Source of truth: [../../../docs/id-sot.md](../../../docs/id-sot.md)

This document describes the clean-slate model implemented by the `aw` CLI.
The important separation is:

- workspace
- identity
- alias
- address

Those are different objects and the CLI should not collapse them into one word.

## Core Objects

### Workspace

A workspace is the local `.aw/` runtime container for one directory.

- It stores local runtime state.
- It may store local signing keys for self-custodial permanent identities.
- It has one active identity at a time.

### Identity

An identity is the principal used for messaging, coordination, and trust.

Two identity classes exist:

- ephemeral
- permanent

Two custody modes matter for permanent identities:

- self-custodial
- custodial

The CLI creates self-custodial identities. Hosted custodial identities are a
dashboard concern.

### Alias

An alias is the routing name used by an ephemeral identity inside its project.

- It is project-scoped routing state.
- It is not the public trust surface.
- It may be auto-assigned.

### Address

An address is the trust-bearing handle for a permanent identity.

- Only permanent identities have addresses in the trust sense.
- The canonical public form is `namespace/name`.
- Narrower forms like `name` or `project~name` are routing/rendering shortcuts.

For compatibility with current server responses, the CLI may still print a
route-like `namespace/name` string for ephemeral identities, but it labels that
as `Routing`, not `Address`.

## What The CLI Creates

### `aw project create`

Usage:

```bash
aw project create --project myteam
```

If the authoritative namespace must differ from the project slug:

```bash
aw project create --project platform --namespace acme
```

Creates:

- a project
- its authoritative namespace
- its first local workspace
- that workspace's first identity

Default outcome:

- ephemeral identity

Explicit alternative:

- `--permanent --name <name>` for a self-custodial permanent identity

### `aw init`

Initializes the current directory as a workspace inside an existing project.

Authority:

- project-scoped API key in `AWEB_API_KEY`

Default outcome:

- ephemeral identity

Explicit alternative:

- `aw init --permanent --name <name>`

`aw init` no longer means “create whatever kind of hosted identity happens to
work with the token.” It is only existing-project workspace init.

### `aw spawn create-invite` / `aw spawn accept-invite`

Spawn is delegated creation of another workspace identity in the same project.

- parent workspace creates a short-lived invite
- child workspace accepts it
- default child identity is ephemeral
- `aw spawn accept-invite --permanent --name <name>` allows explicit
  self-custodial permanent spawn

### `aw connect`

Imports an already-existing identity context from `AWEB_URL` and
`AWEB_API_KEY`.

- It introspects the server state.
- It writes local config and workspace context.
- It does not silently create, claim, or upgrade the identity class.

If the imported identity is a self-custodial permanent identity and no local
signing key is available, the CLI warns instead of inventing a new identity.

## Lifecycle

### Ephemeral identities

User-facing lifecycle verb:

- `delete`

CLI command:

```bash
aw id delete --confirm
```

Effects:

- deletes the current ephemeral identity on the server
- releases its alias
- removes the matching local account/workspace binding
- removes the local signing key if one exists
- if a gone workspace is detected later, `aw workspace status` also deletes the
  corresponding ephemeral identity and removes the stale workspace record

`aw reset` is not an identity lifecycle command. It only removes local
workspace binding state.

### Permanent identities

Permanent identities are not treated as disposable.

Relevant operations:

- `aw id rotate-key`

Archive and replacement belong to the permanent identity model, but this CLI
intentionally omits a fake successor-based command for them.

- `archive` is the normal permanent end-state action
- `replace` is the owner-authorized continuity move after key loss
- both are owner-admin lifecycle flows, not `aw id delete`

## Trust

Trust continuity attaches to permanent addresses, not ephemeral aliases.

- Reusing an ephemeral alias is routing reuse, not continuity.
- A permanent address is the trust surface clients can pin.
- Key rotation and replacement are meaningful only for permanent identities.

## Local State

### Global config

`~/.config/aw/config.yaml` stores:

- servers
- accounts
- API keys
- identity metadata such as DID, stable ID, custody, lifetime, and signing key

### Workspace context

`.aw/workspace.yaml` stores the local workspace binding and coordination state.

- `aw init`, `aw project create`, `aw spawn accept-invite`, `aw connect`, and
  `aw use` update it
- `aw reset` removes it together with `.aw/context`
- `aw id delete --confirm` removes or updates it as part of local
  cleanup

`.aw/context` still stores the local directory's selected saved account name.
- the same bootstrap commands update it by default
- `aw reset` removes it
- `aw id delete --confirm` removes or updates it as part of local cleanup

### Local signing keys

Self-custodial permanent identities store signing keys locally. The CLI must be
able to tell the user where that key lives, because the workspace and key
material are the self-custody boundary.

## Product Language

Preferred CLI language:

- `aw project create`: create a project and first workspace
- `aw init`: initialize this directory as a workspace in an existing project
- `aw spawn`: authorize another workspace to join the same project
- `aw project create --permanent --name <name>`: create a permanent first
  workspace identity
- `aw init --permanent --name <name>`: initialize a workspace with a permanent
  self-custodial identity
- `aw id delete`: delete the current ephemeral identity

Language to avoid:

- “create agent” when the operation is really workspace init
- “address” for ephemeral routing aliases
- vague “reset identity” language that hides whether the action is local reset,
  ephemeral deletion, or permanent continuity change
