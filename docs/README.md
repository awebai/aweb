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
- [Support contract v1](support-contract-v1.md) — public support and diagnostic
  interoperability contract.

</details>

## Non-normative strategy and research

These retained working notes and evidence snapshots do not set product
priority, protocol, or implementation authority. The canonical product SOT
governs when they disagree. References to an external orchestrator describe one
observed composition, not an aweb dependency.

<details>
<summary>Show non-normative strategy and research</summary>

- [Website and dashboard strategy](website-dashboard-strategy.md) — working
  website and hosted-delivery ideas, subordinate to current product direction.
- [Orchestrator evidence review](orchestrator-evidence-review.md) — dated
  research snapshot; OAS is an external reference composition, never a required
  aweb runtime or lifecycle owner.
- [Company-agent platform thesis](company-agent-platform-thesis.md) — retained
  strategy exploration, not the communication-first product contract.
- [Market-entry wedge research](market-entry-wedge-research.md) — subordinate
  discovery hypothesis, not a shipped-feature or roadmap commitment.

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

These are working capabilities outside the first communication journey.
Current optional and advanced helpers remain supported under their documented
contracts; Library/profile services and runtime materialization are opt-in. An
empty-profile, one-repository team is complete, and external orchestrators keep
ownership of definitions, homes, worktrees, runtimes, processes, and session UX.

<details>
<summary>Profiles, runtime, coordination, integrations, and extension contracts</summary>

- [Profiles and blueprints](profiles-and-blueprints.md) — advanced optional
  Library-backed profile helper; empty-profile teams need no profile service.
- [Blueprint materialization contract](blueprint-materialization-contract.md) —
  current advanced optional payload, pin, and provenance contract.
- [Resource-pack template contract](resource-pack-template-contract.md) —
  current advanced optional harness-neutral operating assets.
- [Create and run your first team](create-and-run-team.md) — current optional
  materialized-team helper workflow.
- [Grow an existing team](grow-team.md) — current optional membership-growth
  helper with operator-owned materialization and launch choices.
- [Improve a profile](improve-profile.md) — optional Library-backed reviewed
  profile-learning loop.
- [Running materialized agents](running-agents.md) — advanced optional local
  home/worktree and launch helpers, not an aweb-owned lifecycle.
- [Runtime support](runtime-support.md) — current maintained wake integrations
  and advanced optional materialize/launch helpers.
- [Agent home composition contract](restructuring/agent-home-composition-contract.md)
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
- [Materialize and start one team member](add-ai-tool.md) — optional
  member/home/worktree/runtime workflow.
- [App manifest schema](restructuring/app-manifest-schema.md) — working extension
  contract awaiting relocation out of restructuring material.

</details>

## Experimental

Experimental means implemented or actively specified with a deliberately
narrower stability promise. It does not mean planned commands should be
presented as shipped.

- [A2A interoperability](a2a.md) — experimental external agent protocol surface.
- [Mutation hook seam](aw-hooks-sot.md) — must be rewritten to the public
  `on_mutation` seam actually exposed by source.
- [Hermes gateway integration memo](hermes-aweb-gateway-integration.md) —
  prototype integration evidence.
- [App-emitted events and subscriptions](restructuring/app-event-subscriptions-contract.md)
  — experimental app event contract awaiting relocation.
- [App registry and grants read API](restructuring/app-registry-grants-read-api.md)
  — experimental extension seam awaiting relocation.
- [Session admission leases](session-admission-leases.md) — shipped experimental
  session primitive with explicit non-fencing limits.

## Compatibility and consolidation

These paths remain for current users or because durable facts have not yet been
consolidated. Prefer the canonical/current guide named in each document's status
notice where one exists.

- [Retired agents layout and lifecycle](agents-layout-lifecycle-contract.md) —
  bootstrap-era compatibility.
- [`aw run`](aw-run.md) — current compatibility launcher; opt-in, provider-
  specific, and not an aweb runtime-lifecycle guarantee.
- [Retired bootstrap layout contract](bootstrap-layout-contract.md) — historical
  layout compatibility.
- [Coordination](coordination.md) — overlapping guide pending consolidation.
- [Messaging documentation authority](messaging.md) — compatibility authority
  map for current user, wake, routing, encryption, and conformance documents.
- [Team create and membership model](restructuring/team-create-and-membership-model.md)
  — compatibility command facts pending consolidation.
- [CLI setup surface release gates](setup-surface-release-gates.md) — compatibility
  checks pending consolidation into maintainer guidance.
- [Retired repo-local team bootstrap](team-bootstrap.md) — compatibility
  tombstone.
- [`aw team extend` command SOT](team-extend-sot.md) — shipped compatibility
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
- [Protocol conformance vectors](vectors/README.md) — canonical index currently
  names 8 of 15 tracked JSON fixtures. The seven not yet named there are three
  A2A fixtures, two atomic-address-claim fixtures, the E2E cross-language
  fixture, and team-auth envelope v2; all remain public conformance artifacts.
- [Self-hosted A2A gateway configuration](examples/a2a-gateway.yaml) — retained
  public YAML example for advanced self-hosted/BYOT gateway operation.

The live REST route inventory is the FastAPI `/docs` OpenAPI viewer produced by
`server/src/aweb/api.py`; do not recreate a hand-maintained route reference.

## Maintainer material

- [Contributing guide](contributing.md) — repository structure, tests, and
  extension workflow.
- [Open-source repository boundary](oss-boundary.md) — canonical framework versus
  application ownership and `.aw/` state policy.
- [A2A gateway release runbook](a2a-release-runbook.md) — release and rollback
  controls pending standalone-hosting normalization.
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
- [Federated messaging architecture](federation-architecture.md) — consolidate
  durable rationale into current routing authority, then relocate the snapshot
  to the reviewed historical archive location.
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
  product SOT; current optional profile, payload/pin, resource-pack, growth, and
  runtime-helper facts are extracted in the advanced guides above. Keep this
  narrative non-authoritative until its exact remaining consumers are migrated,
  then remove it rather than restoring its product claims.
- [`aw team extend` implementation plan](team-extend-implementation-plan.md) —
  completed plan; remove because Git/task history is sufficient.

</details>
