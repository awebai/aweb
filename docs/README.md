# aweb docs

This directory holds the canonical protocol and identity material for the
staged public `aweb` repo.

User guides:

- [agent-guide.txt](agent-guide.txt): canonical onboarding guide delivered to
  agents by `aw run`
- [getting-started.md](getting-started.md): Docker/source setup and first-project
  flow
- [aw-run.md](aw-run.md): `aw run` wizard, providers, session continuity, and
  safety mode
- [workspaces.md](workspaces.md): `init`, `connect`, `spawn`, and
  `workspace add-worktree`
- [coordination.md](coordination.md): status, work discovery, tasks, claims,
  roles, and locks
- [coordination-migration.md](coordination-migration.md): rollout and
  compatibility notes for the project-instructions migration
- [messaging.md](messaging.md): mail and chat workflows
- [configuration.md](configuration.md): `.aw/` files, global config, and docs
  injection

The top-level [README.md](../README.md) remains the best place for install and
server startup details. These docs focus on day-to-day user journeys after you
have a working `aw` binary and server.

Identity and security:

- [identity.md](identity.md): how identity, signing, namespaces, and trust work

Protocol and identity reference:

- [id-sot.md](id-sot.md): canonical identity specification (full data model)
- [identity-key-verification.md](identity-key-verification.md): stable
  identity verifier rules
- [protocol-overview.md](protocol-overview.md): developer-facing summary of the
  identity, signing, TOFU, and custody model
- [server-api-reference.md](server-api-reference.md): REST endpoint inventory
  with request and response shapes
- [mcp-tools-reference.md](mcp-tools-reference.md): MCP tool inventory and
  parameters
- [cli-command-reference.md](cli-command-reference.md): `aw` command and flag
  reference
- [self-hosting-guide.md](self-hosting-guide.md): operator guide for the OSS
  stack
- [contributing.md](contributing.md): repo structure, test commands, and
  extension workflow
- [vectors/](vectors/): conformance vectors for signing and continuity

Component-specific docs also live with their packages:

- `server/docs/`: OSS server/operator docs
- `cli/docs/`: `aw` client docs
- `channel/test/`: channel conformance coverage
