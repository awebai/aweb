# aweb documentation

This is the source map for the public aweb repository. It separates shipped
protocol authority, current guides, optional and experimental features, and
compatibility material.

Company strategy, market research, positioning, and private hosted-product
plans deliberately do not live in this OSS repository.

The [repository README](../README.md) has install and server-start commands.
Use this page to find the document you need, and to see which documents carry
authority over shipped behavior.

The baseline contains 71 tracked Markdown documents. This front door does not
self-link. The remaining 70 public Markdown paths appear below exactly once.

## Start here

**Do this first: the [CLI tutorial](cli-tutorial.md).** It is self-contained and
walks the whole round trip from two existing directories — durable send, wake,
reply, and the offline-delivery and reconnect proof. Finishing it means aweb
works for you.

Then, as you need them:

- [Mail and chat](mail-and-chat.md) — everyday messaging patterns beyond the
  round trip.
- [Receiving events and waking agents](receiving-events.md) — wiring wake
  signals into a running agent and recovering after disconnect.
- [Self-hosting guide](self-hosting-guide.md) — operating the OSS services
  yourself. The tutorial's self-hosted path already inlines what you need to
  finish; this is for running them properly.

## How to read the sections below

- **Current protocol authority** governs shipped identity, trust, routing,
  encryption, authentication, and coordination behavior.
- **Guides and references** explain those contracts; they do not override them.
- **Advanced, optional, and experimental** does not mean unsupported or safe to
  delete. These features remain available under their stated lifecycle.
- **Compatibility material** is not current product authority. It remains
  visible for existing users until its reviewed consumer migration or
  consolidation is complete.

Every section is expanded. The two long ones are collapsible for convenience;
collapsing ranks nothing, and no section here is on its way out. Superseded and
completed material is deleted rather than parked, and Git history is its
archive.

## Canonical protocol authority

These documents govern current interoperable behavior. Accuracy notices on
hand-maintained inventories do not weaken their normative security and protocol
authority.

<details open>
<summary>Product, identity, messaging, and trust contracts</summary>

- [Identity and team model](identity.md) — canonical vocabulary and identity/team
  invariants.
- [aweb implementation SOT](aweb-sot.md) — normative aweb server/CLI contract;
  inventory reconciliation is pending.
- [AWID implementation SOT](awid-sot.md) — normative registry contract;
  inventory reconciliation is pending.
- [Product authority SOT](product-authority-sot.md) — current supporting custody,
  team-authority, addressability, and runtime axes pending consolidation.
- [Fully Hosted and BYOT onboarding contract](byot-onboarding-contract.md) —
  authority shapes for managed and customer-controlled teams.
- [Identity and messaging contract](identity-messaging-contract.md) —
  identity-scoped delivery and first-contact routing.
- [Federation error reference](federation-error-reference.md) — generated stable
  reason, HTTP status, retryability, and safe-support contract.
- [Global/local identity routing SOT](global-local-identity-routing.md) — shipped
  global/local route behavior and compatibility cleanup.
- [Identity-key verification](identity-key-verification.md) — verifying current
  AWID identity keys and log heads.
- [E2E messaging contract](e2e-messaging-contract.md) — optional advanced
  encrypted-message v2 envelope and cryptographic binding.
- [E2E operational metadata](e2e-operational-metadata.md) — metadata-only
  operations around encrypted messages.
- [E2E legacy plaintext and no-downgrade policy](e2e-legacy-plaintext-policy.md)
  — mixed-version compatibility rules.
- [Trust model](trust-model.md) — key authority, custody, verification, and
  recovery boundaries.
- [Team-auth request envelope v2](team-auth-envelope-v2.md) — signed relying-party
  request contract.
- [AWID A2A publication contract](a2a-awid-publication-contract.md) — publication
  and bridge-delegation assertions.

</details>

## Core guides

- [Agent guide](agent-guide.md) — compact setup-injected communication and
  recovery contract for an agent.
- [Portable orchestrator integration](orchestrator-integration.md) — persist
  identity/workspace mapping, consume events, reconnect, reply, and retire
  without surrendering runtime ownership.
- [Teams](teams.md) — team membership, roster, and coordination concepts.
- [Identity and teams guide](identity-guide.md) — practical identity, namespace,
  team, and trust operations.
- [Channel](channel.md) — maintained Claude Code event integration.
- [OSS support tools](support-tools.md) — doctor, registry reads, bundles, and
  safe support handoff.
- [Troubleshoot a workspace](troubleshoot-workspace.md) — separate identity,
  membership, durable mailbox, event transport, and runtime wake failures.
- [Mail for beads](beads-mail.md) — turn on `bd mail` with aweb as the
  delegate: three-line setup, addressing, wake-ups, and what differs on purpose.

## Advanced and optional

- [Mail for Gas City](gascity-mail.md) — the same aweb-backed provider for Gas
  City's `GC_MAIL=exec:` seam; one aweb identity per city.

These are working capabilities outside the first communication journey.
Current optional and advanced helpers remain supported under their documented
contracts; Library/profile services and runtime materialization are opt-in. An
empty-profile, one-repository team is complete, and external orchestrators keep
ownership of definitions, homes, worktrees, runtimes, processes, and session UX.

<details open>
<summary>Profiles, runtime, coordination, integrations, and extension contracts</summary>

- [Profiles and blueprints](profiles-and-blueprints.md) — advanced optional
  Library-backed profile helper; empty-profile teams need no profile service.
- [Blueprint materialization contract](blueprint-materialization-contract.md) —
  current advanced optional payload, pin, and provenance contract.
- [Resource-pack template contract](resource-pack-template-contract.md) —
  current advanced optional harness-neutral operating assets.
- [Orchestrate a local agent team](create-and-run-team.md) — current optional
  materialized-team helper workflow.
- [Orchestrate more local agents](grow-team.md) — current optional membership-growth
  helper with operator-owned materialization and launch choices.
- [Improve a profile](improve-profile.md) — optional Library-backed reviewed
  profile-learning loop.
- [Running materialized agents](running-agents.md) — advanced optional local
  home/worktree and launch helpers, not an aweb-owned lifecycle.
- [Runtime support](runtime-support.md) — current maintained wake integrations
  and advanced optional materialize/launch helpers.
- [Agent home composition contract](agent-home-composition-contract.md)
  — current home-layout facts pending consolidation.
- [Start working in your team](start-working.md) — optional task-first workflow
  scheduled for repositioning.
- [Tasks and work](tasks-and-work.md) — current optional shared work
  coordination; external task providers remain valid.
- [Roles, instructions, and locks](roles-instructions-locks.md) — current
  optional team operating context and resource reservation.
- [Work across teams](work-across-teams.md) — multi-team identity and messaging.
- [MCP tutorial](mcp-tutorial.md) — optional MCP client journey scheduled for an
  OSS/hosted split.
- [Materialize a local AI tool](add-ai-tool.md) — optional
  member/home/worktree/runtime workflow.

</details>

## Experimental

Experimental means implemented or actively specified with a deliberately
narrower stability promise. It does not mean planned commands should be
presented as shipped.

- [A2A interoperability](a2a.md) — shipped experimental CLI/gateway and
  self-hosted/BYOT bridge surface.
- [Mutation hook seam](aw-hooks-sot.md) — shipped experimental in-process
  `app.state.on_mutation` callback and exact current route call sites.
- [App manifest v1](app-manifest.md) — current experimental manifest and
  byte-identical CLI interpretation contract.
- [App registry and team grants](app-registry.md) — current experimental install,
  digest-pin, and grants read surface.
- [App-emitted events and subscriptions](app-events.md) — shipped experimental
  emit auth, subscription, SSE, and channel-core consumer contract.
- [Support contract v1](support-contract-v1.md) — current registry-read envelope
  and doctor compatibility boundary; other producers remain experimental.
- [Hermes gateway integration memo](hermes-aweb-gateway-integration.md) —
  prototype integration evidence.
- [Session admission leases](session-admission-leases.md) — shipped experimental
  session primitive with explicit non-fencing limits.

## Compatibility and consolidation

These paths remain for current users or because durable facts have not yet been
consolidated. Prefer the canonical/current guide named in each document's status
notice where one exists.

- [`aw run`](aw-run.md) — opt-in, provider-specific launcher, and the supported
  wake path for Codex today. It sits in this section because aweb does not
  guarantee runtime lifecycle, not because the command is superseded.
- [`aw team admin extend` command SOT](team-extend-sot.md) — shipped compatibility
  contract preserving authority discovery, ambiguity, rollback, and batch
  semantics; use the current growth guide and generated reference for everyday
  operation.

## Generated, reference, and conformance

- [CLI command reference](cli-command-reference.md) — generated from Cobra help;
  live `aw <command> --help` remains the direct source when generation is stale.
- [MCP tools reference](mcp-tools-reference.md) — current tool inventory and
  parameters.
- [Configuration](configuration.md) — local `.aw/` files, environment, and docs
  injection.
- [Current limitations](current-limitations.md) — known operational boundaries.
- [Messaging contract matrix](messaging-contract-matrix.md) — subordinate
  maintainer cases for routing, read state, chat waits, reconnect, and content
  modes.
- [Protocol conformance vectors](vectors/README.md) — canonical index for all 19
  root JSON fixtures, with current, experimental, compatibility, and digest-only
  authority distinguished.
- [Self-hosted A2A gateway configuration](examples/a2a-gateway.yaml) — retained
  public YAML example for advanced self-hosted/BYOT gateway operation.

The live REST route inventory is the FastAPI `/docs` OpenAPI viewer produced by
`server/src/aweb/api.py`; do not recreate a hand-maintained route reference.

## Maintainer material

- [Contributing guide](contributing.md) — repository structure, tests, and
  extension workflow.
- [Open-source repository boundary](oss-boundary.md) — canonical framework versus
  application ownership and `.aw/` state policy.
- [Release process](release.md) — the two-repository release specification:
  local Docker gates once, thin GitHub publication, one global go.
- [A2A gateway release runbook](a2a-release-runbook.md) — public OSS gateway,
  AWID, self-hosted/BYOT release and rollback controls.
- [E2E messaging rollout runbook](e2e-release-rollout-runbook.md) — generic OSS
  compatibility, readiness, evidence, and rollback procedure.
- [Optional Library integration test stack](e2e-library-stack.md) — advanced
  cross-repository maintainer harness; unrelated to encrypted messaging.
- [Per-team agent tmux cutover](agent-tmux-cutover.md) — specialized reviewed
  runtime migration procedure.
- [Beads mail delegate design record](beads-mail-delegate.md) — the decided
  verb surface, identity, threading, retention, and instrumentation choices
  behind `aw beads-mail`.
- [Gas City mail provider design record](gascity-mail-provider.md) — the exec
  contract verified against pinned Gas City source and the operation mapping
  behind `aw gc-mail`.
- [Hosted certificate anchoring draft](drafts/hosted-certificate-anchoring.md) —
  authorized contract for hosted roster read-back; a draft until it lands.
- [Local-sender verification authority draft](drafts/local-sender-verification-authority.md) —
  record of the 2026-08-17 threat-model rulings; the normative text lives in
  the trust model.
