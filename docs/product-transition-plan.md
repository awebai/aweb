# Aweb product transition plan

Status: canonical ordered plan for establishing the communication-product
direction. This plan orders work; it does not itself redefine shipped protocol
or implementation contracts. The product SOT created by Task 1 governs the
target direction once accepted. Existing protocol and implementation SOTs
continue to govern shipped behavior until reviewed changes replace that
behavior.

Owner: Juan (product direction), with one cross-repository coordinator for
execution across the `aweb` and `ac` repositories.

Core product scope: two repositories, `aweb` and `ac`. OAS is a separate third
repository and the reference consumer of the orchestrator integration. Changes
to OAS are coordinated with its owner; OAS is not part of the aweb product
codebase.

## Direction being established

The product shape this plan is intended to establish is:

```text
OAS and other orchestrators
own souls, instances, runtime lifecycle, worktrees, and session UX
        |
        v
aweb / aw
the open communication layer: identity, roster, durable mail, events, wake-up
        |
        v
AWID
the embedded trust and addressability foundation

Optional services: Library, Tasks, Folio, and other integrations.
None is required for a single-repository team.
```

In one sentence:

> OAS runs the team. Aweb lets independently running agents reach and wake one
> another. AWID makes that trustworthy.

The initial wedge is not a comprehensive AI-workforce control plane, a runtime
launcher, a profile marketplace, or a suite of agent apps. It is reliable,
durable communication between independently running agents across sessions,
runtimes, and machines.

## Rules for executing this plan

1. **Replace authority before starting broad implementation.** The first
   product change is one short accepted product SOT, not another large
   architecture proposal alongside the existing ones.
2. **Keep target and current behavior distinct.** A target product contract
   controls direction and priority. A current implementation or protocol
   contract controls shipped behavior until code and tests change.
3. **Supersede product assumptions, not protocol assets.** Identity,
   certificates, routing, encryption, delivery, and current API contracts remain
   authoritative unless a reviewed task explicitly changes them.
4. **Prove the boundary through OAS before redesigning the platform.** OAS is
   the reference consumer because it already owns the concerns aweb should stop
   owning.
5. **Do not require Library.** Profiles and managed sharing remain optional.
   A single repository must be complete without installing or contacting
   Library.
6. **Do not delete shipped features before evidence exists.** First narrow the
   default surface, retain compatibility, measure use, and then decide what can
   retire.
7. **Do not complete architecture extraction for its own sake.** Service
   boundaries follow demonstrated product use; the previous restructuring
   inventories remain useful inputs, not standing implementation authority.
8. **One concern has one canonical document.** Cross-repository documents point
   to the aweb product SOT rather than maintaining divergent copies.
9. **Every task has a gate.** Later work begins only when the preceding task's
   stated outcome and evidence exist.

## Ordered tasks

### 1. Create and accept the canonical product SOT

Create `docs/aweb-product-sot.md`.

Keep it short and decisive. It defines:

- the product promise;
- the initial target user;
- the problem and wedge;
- the boundary between aweb, AWID, OAS/orchestrators, and optional services;
- the default user journey;
- the target default `aw` concepts;
- hosting modes without pretending an unimplemented local mode already exists;
- the relationship between current compatibility and target behavior;
- activation and retention measures;
- explicit non-goals and paused directions;
- precedence over older product and launch documents.

The target promise is:

> Aweb gives independently running agents durable identities, inboxes, and
> wake-up events across sessions, runtimes, and machines.

The initial target users are:

- authors of agent orchestrators;
- developers running different agent harnesses together;
- operators of headless or background agents;
- developers whose independent sessions have outgrown manual message relay.

The initial product does not require:

- Library;
- profiles or blueprints;
- aweb-managed worktrees or agent homes;
- `aw team up`;
- a task tracker;
- an app marketplace;
- understanding AWID vocabulary before first value.

The SOT must contain this precedence rule:

> This SOT controls product direction, prioritization, default onboarding,
> public positioning, and target UX. Existing protocol and implementation SOTs
> continue to control shipped behavior until reviewed implementation changes
> land.

**Gate:** Juan accepts the product promise, boundary, non-goals, default journey,
and precedence rule. No broad product implementation begins before this gate.

### 2. Establish document authority and supersession

In the same reviewed direction change, classify every authoritative document as
one of:

- target product contract;
- current implementation contract;
- protocol contract;
- optional extension contract;
- proposal/draft;
- historical/superseded.

Update `docs/README.md` so the authority chain is explicit:

```text
aweb-product-sot.md
  target, product boundary, priorities, and default UX

aweb-sot.md + awid-sot.md + messaging/E2E contracts
  shipped protocol and implementation behavior

orchestrator-integration-contract.md
  the lifecycle and event interface being built

optional extension contracts
  Library, profiles, Tasks, Folio, A2A, app manifests, and other services
```

Apply these initial classifications:

| Document | Classification |
|---|---|
| `docs/aweb-sot.md` | Current implementation and protocol contract |
| `docs/awid-sot.md` | Protocol contract |
| Identity, routing, messaging, and E2E contracts | Protocol contracts |
| `docs/product-authority-sot.md` | Current supporting technical contract; no positioning authority |
| `docs/launch-readiness-sot.md` | Historical/superseded for launch direction |
| `ac/docs/launch-readiness-sot.md` | Historical/superseded for launch direction |
| `docs/restructuring-sot.md` | Historical/superseded as destination plan; technical inventories retained as research |
| `docs/cli-setup-surface-sot.md` | Current shipped/compatibility contract; not target default UX |
| Team-blueprint SOTs | Optional extension contracts |
| App, secrets, audit, Folio, and manifest SOTs | Optional or paused contracts, not the initial wedge |

Do not delete or move the old documents in this task. Add clear status banners
and preserve links so agents can still determine current behavior and historical
reasoning.

A superseded product document should say:

> **Status: superseded for product direction.** `aweb-product-sot.md` governs
> launch priorities, default onboarding, and public positioning. This document
> is retained as historical design context and must not generate new work.
> Shipped behavior remains governed by the implementation and protocol
> contracts it cites.

An optional profile/blueprint document should say:

> **Status: optional extension contract.** Profiles and blueprints remain
> supported, but are not required by the core communication product or its
> initial activation path.

**Gate:** a reader can determine which document wins for product direction and
which document describes current shipped behavior without relying on team
memory.

### 3. Audit and reclassify the active work

Review every active, ready, and planned task derived from the previous launch or
restructuring direction.

Continue work when it:

- improves identity lifecycle, mail, events, wake-up, delivery reliability, or
  cross-runtime integration;
- is required for security, production reliability, or current compatibility;
- is necessary to prove the new activation journey;
- remains necessary even if Team Builder, Library, and an app marketplace are
  removed from the default path.

Pause work primarily concerned with:

- profile-first onboarding;
- Team Builder as the launch wedge;
- expansion of `aw team up`;
- aweb-owned runtime, home, or worktree management;
- marketplace or naapp proliferation;
- generic gateway composition not required by the communication wedge;
- first-party app expansion unrelated to the wedge;
- deep service extraction justified only by the old destination architecture.

Do not silently cancel work. Record for every affected task whether it
continues, pauses, is re-scoped, or is obsolete, and cite the accepted product
SOT.

**Gate:** no active task contradicts the accepted product boundary, and
reliability/security work needed by current users remains owned.

### 4. Specify the orchestrator integration contract

Create `docs/orchestrator-integration-contract.md`.

This is a narrow executable contract for any orchestrator, with OAS as the
reference consumer. It defines four behaviors.

#### Provision

An orchestrator can provision communication identity for an already-created
agent instance:

- explicit target team;
- explicit instance name;
- explicit identity-home location;
- idempotent;
- non-interactive;
- structured JSON output;
- no profile or Library access;
- no worktree or home materialization beyond identity state;
- no runtime launch;
- no mutation of unrelated agent instructions.

The output contains only what the orchestrator needs:

- canonical team;
- alias/address;
- identity-home location;
- environment or configuration required by the agent;
- event/wake integration information.

The exact CLI spelling is proven in the vertical slice before being frozen.

#### Retire

An orchestrator can retire the instance identity:

- idempotent;
- correctly authorized;
- reachability is removed or revoked with explicit evidence;
- the soul, worktree, and runtime session are untouched.

#### Communicate

- send by stable alias or address;
- durable inbox;
- reply threading;
- explicit acknowledgement;
- idempotent mutations;
- clear delivery and trust status.

#### Receive and wake

The `aw events stream --json` contract specifies:

- stable event identifiers;
- reconnect behavior;
- possible duplicate delivery;
- cursor or replay semantics;
- acknowledgement timing;
- ordering guarantees;
- stable fields;
- cold-start handling;
- how a runtime adapter translates an event into a wake-up.

**Gate:** the contract is precise enough to encode as end-to-end tests without
inventing behavior in the test.

### 5. Encode the communication journey as a failing vertical-slice test

Create a real end-to-end test against the real aweb and AWID stack.

The scenario is:

1. An orchestrator owns an existing team.
2. It provisions two agent identities without profiles or runtime
   materialization.
3. Agent A sends durable mail to Agent B.
4. Agent B's event consumer receives the event.
5. Agent B acknowledges and replies.
6. Agent A's event consumer receives the reply.
7. Consumers reconnect without losing durable state and tolerate documented
   replay.
8. The orchestrator retires both identities.
9. The test verifies the promised reachability cleanup.

The test must fail against the missing lifecycle or event behavior for the
right reason before implementation begins.

**Gate:** the failing test captures the complete initial product proof and uses
no mocks for identity, delivery, or events.

### 6. Implement the smallest provision/retire primitive

Implement only enough lifecycle behavior to satisfy the accepted integration
contract and vertical-slice test.

Do not include:

- profile selection;
- Library calls;
- role templates;
- agent-home composition;
- worktree creation;
- tmux or runtime launch;
- task-system setup.

Preserve current invite/join/setup commands as compatibility surfaces. The new
primitive may compose current internals, but the orchestrator-facing operation
must be one idempotent action with structured results.

**Gate:** the lifecycle portion of the vertical-slice test passes, repeated
provision/retire calls are safe, and failure output distinguishes partial
creation from verified success.

### 7. Make event delivery a supported headless integration surface

Implement or document any missing behavior required by the accepted event
contract:

- stable identity for delivered events;
- reconnect and replay behavior;
- duplicate-handling guidance;
- acknowledgement semantics;
- cold-start handoff;
- bounded retry/failure behavior;
- clean JSON suitable for an orchestrator.

Runtime-specific channel plugins remain adapters over this contract. The
headless event stream is the portable integration surface.

**Gate:** the full mail/wake/reply/reconnect portion of the vertical-slice test
passes without polling and without a runtime-specific plugin.

### 8. Convert OAS to the new boundary

Replace OAS's current multi-step aweb lifecycle sequence with the accepted
provision/retire primitive.

OAS continues to own:

- souls and instances;
- agent homes;
- worktrees;
- runtime selection and launch;
- knowledge;
- task-provider selection;
- session UX.

Aweb supplies:

- identity;
- team reachability;
- roster;
- durable mail;
- events and wake-up configuration;
- retirement of communication identity.

The OAS integration must not make Library or aweb tasks implicit dependencies.

**Gate:** a real OAS instance can be spawned, reached, awakened, replied to, and
retired through the narrow integration, and the previous invite/join/init
sequence is no longer implemented in OAS.

### 9. Dogfood the complete journey

Use the new integration for real coordination work.

Record:

- setup steps still requiring a human;
- lifecycle failures and partial-state recovery;
- incorrect wake-ups;
- duplicate or missing events;
- time from send to the correct runtime receiving work;
- identity cleanup failures;
- concepts OAS must understand that should remain inside aweb.

Fix root causes within the accepted boundary. Do not respond to dogfood friction
by moving runtime or task ownership back into aweb.

**Gate:** the OAS team uses the new path for normal work without a special
operator playbook.

### 10. Decide the clean-user quickstart

The existing self-hosted local stack requires aweb, AWID, PostgreSQL, Redis, and
Docker Compose. Do not describe it as a frictionless local-first path.

Compare three explicit options:

1. an instant, limited hosted communication scope that can be claimed later;
2. a genuinely bundled local relay;
3. the existing Docker self-hosted stack for operators.

Evaluate:

- time to first two-agent round trip;
- security and abuse boundaries;
- account requirements;
- offline behavior;
- implementation cost;
- whether the option preserves the OSS/self-hostable promise;
- migration from the quickstart to durable hosted or self-hosted operation.

The initial acquisition path may use an expiring, unclaimed hosted scope if it
is team-internal, strictly limited, and lets a user experience value before
choosing an account. A bundled local relay is not authorized merely because it
would improve the story; it requires evidence that local-only operation blocks
adoption enough to justify the implementation.

**Gate:** one quickstart shape is accepted with an explicit trust, expiry,
claim, and migration contract.

### 11. Implement and test the clean-user activation path

From a clean environment, a user must be able to:

1. install `aw`;
2. establish a communication scope without Library;
3. connect or provision two independent agents;
4. send a message;
5. wake the intended recipient;
6. receive a reply;
7. understand the next step for persistence, cross-machine use, or self-hosting.

The path must not teach:

- profile-selector grammar;
- app manifests;
- A2A;
- BYOT internals;
- certificate identifiers;
- task/role/lock commands;
- tmux or worktree creation.

**Gate:** a new user completes the round trip without founder assistance, and
the measured activation is the successful round trip rather than account or
team creation.

### 12. Narrow the visible `aw` surface

Keep shipped commands compatible while making the default surface reflect the
communication product.

The default concepts are:

- connect/init;
- provision/retire;
- roster/status;
- send/inbox/reply;
- events/watch;
- doctor/self-host.

Move protocol administration, profiles, tasks, roles, locks, plugins, A2A, and
runtime management out of the first-run and default-help journey. Keep them
discoverable through advanced help and reference documentation while usage and
compatibility evidence is collected.

Update generated agent instructions so they teach only the capabilities needed
by the selected integration.

**Gate:** a first-time user can read default help without having to understand
the larger historical platform.

### 13. Replace the public story and first-run documentation

Make the homepage prove one behavior:

```text
Claude sends to Codex
  -> Codex wakes
  -> Codex replies
  -> Claude wakes
```

The public promise is:

> Your agents need an inbox. Give Claude Code, Codex, Pi, and headless workers
> durable mail and wake-up events across sessions, machines, and orchestrators.

Keep:

> Stop being their message bus.

Primary paths:

- connect two agents;
- integrate an orchestrator;
- see it working in OAS.

Remove Team Builder, blueprint grammar, Library, naapps, the org chart, A2A,
custody models, and broad pricing from the primary activation journey.

Publish a small first-run documentation set:

1. connect two agents;
2. integrate an orchestrator lifecycle;
3. mail delivery, reply, acknowledgement, and idempotency;
4. events, reconnect, replay, and wake-up;
5. hosted relay, self-hosting, identity, and trust.

Everything else remains available as reference or optional-extension
documentation.

**Gate:** every homepage claim is demonstrated by the shipped activation path,
and every primary call to action reaches that path.

### 14. Validate with one external orchestrator

Choose one receptive external project. Integrate through the public contract
without giving the integrator private architectural knowledge.

Measure:

- integration effort;
- concepts the integrator had to learn;
- lifecycle correctness;
- wake-up correctness;
- behavior across at least two runtimes;
- whether documentation alone was sufficient;
- support required from the aweb team.

Do not treat an integration maintained entirely by the aweb team as proof of
independent comprehensibility.

**Gate:** an external orchestrator uses provision, mail, events, wake-up, and
retire through the documented contract and chooses to keep the integration.

### 15. Recruit and observe real teams

Recruit users from the initial target communities:

- orchestrator authors;
- mixed-harness power users;
- headless-agent builders;
- teams already operating multiple independent sessions.

Observe:

- completion of first round trip;
- continued meaningful agent-to-agent communication;
- cross-runtime or cross-machine use;
- failure recovery;
- founder/support intervention;
- demand for tasks, chat, profiles, local-only operation, or managed identity.

Do not use package downloads, identities created, or empty teams as the primary
evidence of traction.

**Gate:** external teams repeatedly use the communication path and the team can
name the next constraint from observed behavior rather than architectural
preference.

### 16. Decide what to retire, retain, or promote

Only after external evidence exists, decide:

- whether mail remains bundled product behavior or becomes an internal app
  boundary;
- whether synchronous chat earns a primary surface;
- whether a lightweight aweb task provider is wanted;
- whether an embedded local relay is necessary;
- whether profiles belong only in OAS/Library;
- whether app grants and manifests have independent demand;
- whether AWID has a separate platform-builder wedge;
- which existing `aw` commands can enter deprecation.

For each surface:

- retain and promote;
- retain as optional/advanced;
- deprecate with a compatibility window;
- remove only after usage and migration evidence.

**Gate:** retirement decisions cite observed use, compatibility impact, and a
migration path.

### 17. Revisit service architecture

Use the validated product boundary to decide the destination architecture.

The earlier restructuring work remains a source of:

- current table/router/tool inventories;
- service seams;
- migration risks;
- app-auth and event-channel research;
- extraction sequencing hazards.

It no longer authorizes decomposition by itself.

Architecture work begins only where it:

- makes the validated communication product simpler or more reliable;
- isolates optional services from the core path;
- reduces operational coupling demonstrated to be harmful;
- enables required local, hosted, or cross-machine behavior;
- preserves protocol and migration safety.

**Gate:** each architectural change is justified by the validated product
contract and has its own reviewed migration and rollback evidence.

## Measures

The activation measure is:

> Two independently running agents exchange a durable message, including
> recipient wake-up and reply delivery, without founder assistance.

Supporting measures:

- time and number of decisions from install to first round trip;
- successful reconnect without lost durable state;
- correct-recipient wake-up rate;
- provision and retirement success, including idempotent retry;
- external orchestrator integration effort;
- meaningful recurring communication by external teams;
- cross-runtime and cross-machine use;
- support interventions per activation;
- demand for optional services after communication is already working.

## Work that remains authorized during the transition

The direction change does not freeze necessary maintenance. Continue:

- security fixes;
- production reliability;
- data and migration safety;
- identity, encryption, routing, and delivery correctness;
- compatibility fixes for shipped users;
- release integrity;
- defects that block the communication vertical slice.

When maintenance overlaps a superseded product surface, make the smallest safe
fix and do not expand that surface without an explicit product decision.

## First action

The next task after this plan is accepted is Task 1:

> Draft, review, and accept `docs/aweb-product-sot.md`, then apply the document
> authority and supersession changes from Task 2 in the same direction-setting
> change.

No broad implementation or public relaunch should precede that accepted
authority change.
