# aweb documentation

This is the source map for the public aweb repository. It separates target
product direction, shipped protocol authority, current guides, optional and
experimental features, compatibility material, and documents waiting for their
reviewed transition.

The [repository README](../README.md) has install and server-start commands.
Use this page to decide which document has authority after the stack is running.

## How authority works

- **Target direction** answers what product is being built and which journey
  comes first. It does not claim an API or command already ships.
- **Current protocol authority** governs shipped identity, trust, routing,
  encryption, authentication, and coordination behavior.
- **Guides and references** explain those contracts; they do not override them.
- **Advanced, optional, and experimental** does not mean unsupported or safe to
  delete. These features remain available under their stated lifecycle.
- **Compatibility and transition material** is not current product authority.
  It remains visible until its reviewed consumer migration, consolidation, or
  removal is complete.

The baseline contains 102 tracked Markdown documents. This front door does not
self-link, and four private-purpose Markdown artifacts are deliberately not
exposed by public path or title. The remaining 97 public Markdown paths appear
below exactly once. Those four artifacts and one private-purpose configuration
example remain represented by neutral, unlinked transition descriptions until
their later consumer-ordered relocation or removal.

## Start here

The shortest current path is:

1. [CLI tutorial](cli-tutorial.md) — complete the hosted or self-hosted durable
   send, wake, reply, and reconnect round trip from two existing directories.
2. [Mail and chat](mail-and-chat.md) — send durable mail, open chat, and reply.
3. [Receiving events and waking agents](receiving-events.md) — connect wake
   signals to a running agent and recover after disconnect.
4. [Self-hosting guide](self-hosting-guide.md) — run the OSS services yourself.

## Canonical product and protocol authority

These documents govern direction or current interoperable behavior. The product
SOT governs priorities; implementation/protocol SOTs govern what ships today.
Accuracy notices on hand-maintained inventories do not weaken their normative
security and protocol authority.

<details open>
<summary>Product, identity, messaging, and trust contracts</summary>

- [Aweb product SOT](aweb-product-sot.md) — canonical communication-first target
  direction and ownership boundaries.
- [Website and dashboard strategy](website-dashboard-strategy.md) — working
  strategy for the public site, documentation journey, integration pages, and
  hosted delivery dashboard.
- [Orchestrator evidence review](orchestrator-evidence-review.md) — research
  snapshot separating demonstrated orchestrator capabilities from unproven
  agent-fleet productivity claims.
- [Company-agent platform thesis](company-agent-platform-thesis.md) — working
  strategy for trusted, specialized, learning company agents, beginning with
  two agents on one real workflow.
- [Market-entry wedge research](market-entry-wedge-research.md) — subordinate
  discovery hypothesis for paid production rescues of a narrow class of
  existing fragile agent workflows.
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

## Advanced and optional

These are working capabilities outside the first communication journey. They
remain supported or are awaiting a focused rewrite/relocation; Library-backed
profiles and runtime materialization are optional.

<details>
<summary>Profiles, runtime, coordination, integrations, and extension contracts</summary>

- [Profiles and blueprints](profiles-and-blueprints.md) — optional profile and
  blueprint concepts.
- [Blueprint materialization contract](blueprint-materialization-contract.md) —
  public payload, pin, and provenance contract.
- [Resource-pack template contract](resource-pack-template-contract.md) —
  harness-neutral operating assets.
- [Create and run your first team](create-and-run-team.md) — optional
  materialized-team workflow.
- [Grow an existing team](grow-team.md) — optional team expansion workflow.
- [Improve a profile](improve-profile.md) — reviewed profile learning loop.
- [Running materialized agents](running-agents.md) — local runtime launch and
  home isolation.
- [Runtime support](runtime-support.md) — supported harness/runtime matrix.
- [Agent home composition contract](restructuring/agent-home-composition-contract.md)
  — current home-layout facts pending consolidation.
- [Start working in your team](start-working.md) — task-first workflow scheduled
  for repositioning.
- [Tasks and work](tasks-and-work.md) — advanced shared work coordination.
- [Roles, instructions, and locks](roles-instructions-locks.md) — advanced team
  operating context.
- [Work across teams](work-across-teams.md) — multi-team identity and messaging.
- [MCP tutorial](mcp-tutorial.md) — optional MCP client journey scheduled for an
  OSS/hosted split.
- [Materialize and start one team member](add-ai-tool.md) — optional
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

- [Retired agents layout and lifecycle](agents-layout-lifecycle-contract.md) —
  bootstrap-era compatibility.
- [`aw run`](aw-run.md) — compatibility/session launcher guide.
- [Retired bootstrap layout contract](bootstrap-layout-contract.md) — historical
  layout compatibility.
- [Coordination](coordination.md) — overlapping guide pending consolidation.
- [Messaging](messaging.md) — overlapping guide pending correction and
  consolidation into the canonical messaging workflow.
- [Team create and membership model](restructuring/team-create-and-membership-model.md)
  — compatibility command facts pending consolidation.
- [CLI setup surface release gates](setup-surface-release-gates.md) — compatibility
  checks pending consolidation into maintainer guidance.
- [Retired repo-local team bootstrap](team-bootstrap.md) — compatibility
  tombstone.
- [`aw team extend` command SOT](team-extend-sot.md) — compatibility semantics
  pending consolidation into guides and generated reference.

## Generated, reference, and conformance

- [CLI command reference](cli-command-reference.md) — generated from Cobra help;
  live `aw <command> --help` remains the direct source when generation is stale.
- [MCP tools reference](mcp-tools-reference.md) — current tool inventory and
  parameters.
- [Configuration](configuration.md) — local `.aw/` files, environment, and docs
  injection.
- [Current limitations](current-limitations.md) — known operational boundaries.
- [Messaging contract matrix](messaging-contract-matrix.md) — conformance and
  release-case inventory pending maintainer consolidation.
- [Protocol conformance vectors](vectors/README.md) — canonical index for all 15
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
- [A2A gateway release runbook](a2a-release-runbook.md) — public OSS gateway,
  AWID, self-hosted/BYOT release and rollback controls.
- [E2E messaging rollout runbook](e2e-release-rollout-runbook.md) — generic OSS
  compatibility, readiness, evidence, and rollback procedure.
- [Optional Library integration test stack](e2e-library-stack.md) — advanced
  cross-repository maintainer harness; unrelated to encrypted messaging.
- [Per-team agent tmux cutover](agent-tmux-cutover.md) — specialized reviewed
  runtime migration procedure.

## Superseded and temporary transition material

> **Non-authoritative transition inventory.** Nothing in this section sets
> current product direction or creates new work. Files remain at their current
> paths only until the reviewed extraction and consumer-migration conditions are
> met. Git and durable task history are sufficient for removed material; no
> duplicate archive is implied unless a reviewed row explicitly requires
> archival treatment.

<details>
<summary>Show the transition inventory and reviewed next action</summary>

- **Managed A2A gateway application contract** — private-purpose Markdown,
  deliberately unlinked; relocate to its application owner after the public
  release-runbook consumer is rewritten.
- **Managed A2A gateway configuration example** — private-purpose YAML,
  deliberately unlinked; relocate with the application contract after its
  public consumer is rewritten.
- **Hosted custody implementation contract** — private-purpose Markdown,
  deliberately unlinked; extract public custody/interoperability semantics into
  canonical E2E contracts, then relocate the implementation detail to its
  application owner.
- [aapm.6 equivalence evidence](aapm6-equivalence-evidence.md) — relocate as
  dated, unrendered migration history.
- [AWID registry-unavailable log](awid-registry-unavailable-log.md) — move useful
  incident facts to current operational/task history and remove from rendered
  docs.
- [Bootstrapping operating-patterns worklog](bootstrapping-operating-patterns-worklog.md)
  — remove after reusable facts and consumers are migrated.
- [aw setup surface taxonomy](cli-setup-surface-sot.md) — superseded product SOT;
  consolidate current command taxonomy, then retire it.
- [Agent-guide running-agents draft](drafts/agent-guide-running-agents-update.md)
  — remove after confirming incorporated text.
- [Duplicate 1:1 conversation cleanup](duplicate-1to1-conversation-cleanup.md) —
  remove after consumer migration and reusable-authority extraction.
- [Federated messaging architecture](federation-architecture.md) — durable rules
  are consolidated in current routing authority; relocate this historical
  snapshot during the reviewed archive/pruning lane.
- [Launch readiness](launch-readiness-sot.md) — superseded product narrative;
  extract current facts and remove after index/consumer migration.
- [naapp move preflight](naapp-move-preflight.md) — completed preflight; remove
  after consumer checks.
- [Pre-deploy conversation-close cleanup](pre-deploy-conversation-close-cleanup.md)
  — completed one-time procedure; remove after reusable warnings are extracted.
- [Restructuring SOT](restructuring-sot.md) — superseded destination architecture;
  extract still-current protocol facts, migrate links, then remove with no
  duplicate archive.
- **Application cross-boundary FK inventory** — private-purpose Markdown,
  deliberately unlinked; repoint its exact downstream consumers, then remove
  the public copy.
- [Agent instantiation runbook](restructuring/agent-instantiation-runbook.md) —
  remove after its skill consumer and valid runtime facts migrate.
- [Archived channel stack map](restructuring/archive/channel-stack-map.md) — the
  one retained dated/SHA-bound historical archive; never current authority.
- [aw command surface](restructuring/aw-command-surface.md) — remove after current
  command facts are covered by live/generated reference.
- [Go CLI restructuring map](restructuring/cli-go-map.md) — remove after its path
  checker consumer and current facts migrate; no archive copy.
- [Core-surface shrink scorecard](restructuring/core-surface-shrink-scorecard.md)
  — remove after any reusable measurement becomes maintainer tooling.
- [Restructuring decisions worksheet](restructuring/decisions.md) — remove;
  durable decisions belong in current authority and task history.
- [Layer mapping](restructuring/layer-mapping.md) — remove after current extension
  contracts are extracted; no archive copy.
- [Messaging-as-app seam](restructuring/messaging-as-app-seam.md) — remove after
  current messaging invariants move to canonical contracts; no archive copy.
- [OSS core inventory](restructuring/oss-core-inventory.md) — remove after reusable
  inventory checks become current tooling; no archive copy.
- [Scrapped team-certificate issuer seam](restructuring/team-cert-issuer-seam.md)
  — remove after its historical memory consumer points to Git/task history.
- **Production migration evidence runbook** — private-purpose Markdown,
  deliberately unlinked; relocate to its production-operations owner after
  consumer migration.
- [Team blueprints and agent profiles](team-blueprints-sot.md) — superseded
  product SOT; consolidate verified advanced materialization facts, then remove
  the competing narrative.
- [`aw team extend` implementation plan](team-extend-implementation-plan.md) —
  completed plan; remove because Git/task history is sufficient.

</details>
