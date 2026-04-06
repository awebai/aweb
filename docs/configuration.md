# Configuration

This guide covers the local files that make `aw` work in a repo or worktree.

## User State: `~/.config/aw/`

The CLI still uses a small user-state directory, but it no longer has a global
account/config file.

Current files include:

- `~/.config/aw/known_agents.yaml`: TOFU pins for peer identity verification
- `~/.config/aw/run.json`: optional `aw run` defaults

## Worktree Signing Key: `.aw/signing.key`

Self-custodial workspace identities store their active private signing key in:

```text
.aw/signing.key
```

The key material itself is worktree-local.

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
- `workspace_id`
- `repo_id`
- `canonical_origin`
- `role_name`

This file is what makes worktree-aware commands like `aw workspace status`,
`aw workspace add-worktree`, and `aw run` coordination-aware, and it is also
the first local source of truth for binding a directory to a project identity.

For permanent identities, cryptographic identity state lives in
`.aw/identity.yaml`, not in `.aw/workspace.yaml`.

## Permanent Identity State: `.aw/identity.yaml`

Permanent identities store their durable identity data in:

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

## Local Context: `.aw/context`

`.aw/context` is a small non-secret local coordination pointer.

Bootstrap commands such as `aw project create`, `aw init`, and
`aw spawn accept-invite` write it by default unless you pass
`--write-context=false`.

## Resolution Order

When more than one config source is present, the effective selection order is:

1. CLI flags such as `--server-name`
2. environment variables such as `AWEB_URL` and `AWEB_API_KEY`
3. local `.aw/workspace.yaml`
4. local `.aw/identity.yaml` for permanent identity fields
5. local `.aw/context`

That means a directory-local `.aw/` tree fully binds one repo or worktree.

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

## Server Environment Variables

The server also relies on a small set of deployment-time environment variables.
These are not stored in `.aw/`, but they determine how permanent identity
resolution and custodial signing behave.

### Identity Resolution

- `AWID_REGISTRY_URL`: selects the awid registry origin. The server default is
  `https://api.awid.ai`. The OSS Docker Compose stack overrides this to
  `http://awid:8010`.
- `APP_ENV`: when set to `production` or left unset, registry URLs must use
  HTTPS. Only explicit development values such as `dev`, `development`, or
  `local` relax that check.

### Managed Namespace Control

- `AWEB_MANAGED_DOMAIN`: the parent domain used for server-managed permanent
  addresses
- `AWEB_NAMESPACE_CONTROLLER_KEY`: 64-char hex Ed25519 seed used to sign
  namespace and address registrations for `AWEB_MANAGED_DOMAIN` against awid

### Custodial Agent Signing

- `AWEB_CUSTODY_KEY`: 64-char hex key used to decrypt custodial agent signing
  keys and sign payloads on behalf of custodial identities

The two signing keys serve different roles:

- `AWEB_CUSTODY_KEY` is for agent-level custodial signing
- `AWEB_NAMESPACE_CONTROLLER_KEY` is for namespace/address control at the awid
  registry

If you run with `APP_ENV=production`, keep `AWID_REGISTRY_URL` on HTTPS and
set both keys consistently across all app instances that need those features.
