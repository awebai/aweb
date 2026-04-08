# aweb docs

This directory holds the canonical protocol, identity, and user material for
the public `aweb` repo.

## Source of truth

These two documents define the system:

- [team-architecture-sot.md](team-architecture-sot.md): the implementation
  spec for the `aweb` server and `aw` CLI under the awid teams architecture,
  including the conceptual taxonomy (agent, workspace, identity, alias,
  address, lifecycle)
- [awid-team-architecture-sot.md](awid-team-architecture-sot.md): the awid
  service spec for namespaces, addresses, the DID registry, teams, and
  membership certificates

## User guides

- [agent-guide.txt](agent-guide.txt): canonical onboarding guide delivered to
  agents by `aw run`
- [aw-run.md](aw-run.md): `aw run` wizard, providers, session continuity, and
  safety mode
- [coordination.md](coordination.md): status, work discovery, tasks, claims,
  roles, and locks
- [messaging.md](messaging.md): mail and chat workflows
- [identity.md](identity.md): how identity, signing, namespaces, and trust
  work in practice
- [configuration.md](configuration.md): `.aw/` files, global config, and docs
  injection
- [channel.md](channel.md): Claude Code channel — real-time push events,
  setup, and event reference

The top-level [README.md](../README.md) is the best place for install and
server startup details. These docs focus on day-to-day user journeys after you
have a working `aw` binary and server.

## Reference

- [cli-command-reference.md](cli-command-reference.md): `aw` command and flag
  reference (generated from the live Cobra help tree)
- [server-api-reference.md](server-api-reference.md): REST endpoint inventory
  with request and response shapes
- [mcp-tools-reference.md](mcp-tools-reference.md): MCP tool inventory and
  parameters
- [identity-key-verification.md](identity-key-verification.md): normative
  rules for verifying `GET /v1/did/{did_aw}/key` responses
- [self-hosting-guide.md](self-hosting-guide.md): operator guide for the OSS
  stack
- [contributing.md](contributing.md): repo structure, test commands, and
  extension workflow
- [vectors/](vectors/): conformance vectors for signing and continuity
