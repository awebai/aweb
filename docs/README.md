# aweb docs

This directory holds the canonical protocol and identity material for the
staged public `aweb` repo.

User guides:

- [getting-started.md](getting-started.md): Docker/source setup and first-project
  flow
- [aw-run.md](aw-run.md): `aw run` wizard, providers, session continuity, and
  safety mode
- [workspaces.md](workspaces.md): `init`, `connect`, `spawn`, and
  `workspace add-worktree`
- [coordination.md](coordination.md): status, work discovery, tasks, claims,
  roles, and locks
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
- [vectors/](vectors/): conformance vectors for signing and continuity

Component-specific docs also live with their packages:

- `server/docs/`: OSS server/operator docs
- `cli/docs/`: `aw` client docs
- `channel/test/`: channel conformance coverage
