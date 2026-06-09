# aweb docs

This directory holds the canonical protocol, identity, and user material for
the public `aweb` repo.

Public documentation should live under `https://aweb.ai/docs/`. Agent-facing
Markdown is served as `https://aweb.ai/docs/<name>.md`, and the human-readable
HTML rendering is served as `https://aweb.ai/docs/<name>/`.

## Source of truth

These documents define the system:

- [aweb-sot.md](aweb-sot.md): the implementation
  spec for the `aweb` server and `aw` CLI under the awid teams architecture,
  including the conceptual taxonomy (agent, workspace, identity, alias,
  address, lifecycle)
- [awid-sot.md](awid-sot.md): the awid
  service spec for namespaces, addresses, the DID registry, teams, and
  membership certificates
- [identity-messaging-contract.md](identity-messaging-contract.md): the
  cross-service contract for identity-scoped mail/chat, address-route first
  contact, recipient binding, and local fallback rules
- [e2e-messaging-contract.md](e2e-messaging-contract.md): the normative
  encrypted message v2 envelope, cryptographic binding, no-downgrade, and
  metadata-leakage contract
- [e2e-operational-metadata.md](e2e-operational-metadata.md): metadata-only
  usage, billing, abuse, retention, support, and admin tooling contract for v2
  E2E messages
- [e2e-legacy-plaintext-policy.md](e2e-legacy-plaintext-policy.md): legacy
  plaintext, explicit plaintext escape hatch, no-downgrade, and mixed-version
  compatibility policy for E2E rollout
- [e2e-release-rollout-runbook.md](e2e-release-rollout-runbook.md): release
  sequencing, mixed-version matrix, observability, and rollback checklist for
  encrypted message v2 rollout
- [global-local-identity-routing.md](global-local-identity-routing.md):
  supporting SOT for the shipped route-level global/local messaging contract
  and the legacy reachability/conversation-auth cleanup path
- [product-authority-sot.md](product-authority-sot.md): supporting SOT for
  identity custody, addressability, team authority, runtime hosting, app
  portability, and the supported terminal/browser composition paths
- [byot-onboarding-contract.md](byot-onboarding-contract.md): the product and
  engineering contract for the two supported onboarding shapes: Fully Hosted
  and BYOT
- [cli-setup-surface-sot.md](cli-setup-surface-sot.md): supporting SOT for
  the `aw` team/identity/setup command taxonomy: everyday intents, agent
  primitives, protocol/admin primitives, and obsolete/legacy compatibility
- [team-blueprints-sot.md](team-blueprints-sot.md): product SOT for team
  blueprints — repos of souls, roles, skills, and playbooks that an agent
  uses to create a team in the human's repo; defines the souls/instances
  model, vocabulary, target layout, and blueprint contents
- [resource-pack-template-contract.md](resource-pack-template-contract.md):
  supporting SOT for new-design templates that package harness-neutral roles,
  instructions, playbooks, skills, and adapters without identity/workspace state;
  see `resource-packs/coord-workflows` and `resource-packs/company-surfaces`
  for successor resource packs to the bootstrap-era templates
- [setup-surface-release-gates.md](setup-surface-release-gates.md): release
  checklist and regression gates for the primitive-first setup surface
- [bootstrap-layout-contract.md](bootstrap-layout-contract.md): legacy/
  compatibility contract for the in-repo `agents/` bootstrap convention and
  generated agent-home layout. The current setup-surface product taxonomy is
  [cli-setup-surface-sot.md](cli-setup-surface-sot.md).
- [a2a.md](a2a.md): product contract for exposing aweb agents through A2A,
  AWID publication assertions, gateway boundaries, and outbound `aw a2a`
  behavior
- [a2a-awid-publication-contract.md](a2a-awid-publication-contract.md):
  normative AWID A2A publication and bridge-delegation assertion contract
- [a2a-release-runbook.md](a2a-release-runbook.md): release sequencing, live
  verification, site-copy gates, and rollback checklist for the A2A gateway
  product slice

## User guides

- [cli-tutorial.md](cli-tutorial.md): first-run tutorial for agents using the
  `aw` CLI
- [mcp-tutorial.md](mcp-tutorial.md): first-run tutorial for agents using the
  aweb MCP tools
- [agent-guide.md](agent-guide.md): canonical onboarding guide delivered to
  agents by `aw run`
- [aw-run.md](aw-run.md): `aw run` wizard, providers, session continuity, and
  safety mode
- [coordination.md](coordination.md): status, work discovery, tasks, claims,
  roles, and locks
- [messaging.md](messaging.md): mail and chat workflows
- [identity.md](identity.md): how identity, signing, namespaces, and trust
  work in practice
- [trust-model.md](trust-model.md): trust boundaries, key authority, custody,
  and recovery semantics
- [support-tools.md](support-tools.md): OSS `aw doctor`, registry read,
  support bundle, lifecycle, E2E support boundary, and high-impact handoff
  semantics
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
- [mcp-tools-reference.md](mcp-tools-reference.md): MCP tool inventory and
  parameters

The REST API surface is the canonical FastAPI app at
[`server/src/aweb/api.py`](../server/src/aweb/api.py); use the `/docs`
OpenAPI viewer at runtime for the live route inventory.
- [identity-key-verification.md](identity-key-verification.md): normative
  rules for verifying `GET /v1/did/{did_aw}/key` responses
- [self-hosting-guide.md](self-hosting-guide.md): operator guide for the OSS
  stack
- [contributing.md](contributing.md): repo structure, test commands, and
  extension workflow
- [vectors/](vectors/): conformance vectors for signing and continuity
