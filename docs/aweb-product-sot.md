# Aweb product SOT

Status: canonical target product contract.

This document governs product direction, prioritization, default onboarding,
public positioning, and target user experience across the `aweb` and `ac`
repositories.

Existing protocol and implementation SOTs continue to govern shipped behavior
until reviewed code, tests, and documentation change that behavior. This
document does not silently redefine an API, wire format, trust rule, migration,
or currently supported command.

## Product promise

> Aweb gives independently running agents durable identities, inboxes, and
> wake-up events across sessions, runtimes, and machines.

In plainer language:

> Your agents need an inbox. Stop being their message bus.

Aweb succeeds when one independently running agent can reliably reach another,
wake the correct runtime, receive a reply, and continue the conversation after
either process restarts.

## Initial users

The initial product is for:

- authors of agent orchestrators;
- developers running different agent harnesses together;
- operators of headless or background agents;
- developers whose independent sessions have outgrown manual message relay.

The initial wedge is communication among agents that already exist. It is not
the creation of a complete AI workforce, a profile marketplace, or a runtime
launcher.

## Product boundaries

### Aweb and `aw`

Aweb is the open communication layer. It owns:

- communication identity and team reachability;
- the roster needed to address another agent;
- durable mail and reply threading;
- delivery events and acknowledgements;
- a portable headless event stream;
- wake-up integration contracts;
- communication-identity provisioning and retirement;
- self-hostable protocol and server behavior.

The target `aw` surface makes these capabilities understandable and scriptable.

### AWID

AWID is the embedded trust and addressability foundation. It owns the identity,
team-membership, certificate, routing, and verification contracts that make
communication trustworthy.

Users should not need to learn AWID terminology before their first successful
agent-to-agent exchange.

### AC

AC is the hosted aweb service and human-facing product surface. It owns hosted
accounts, organizations, billing, hosted team and identity operations, the
dashboard, and the public website.

The core aweb product is implemented across two repositories: public `aweb` and
private `ac`.

### Orchestrators

Orchestrators own:

- souls and reusable agent definitions;
- instances;
- agent homes and knowledge;
- worktrees;
- runtime selection and process lifecycle;
- session user experience;
- task-provider selection.

An orchestrator provisions communication identity for an agent it already
created. Aweb does not take ownership of that agent's soul, worktree, runtime,
or task system.

OAS is a separately owned repository and the reference consumer for the initial
orchestrator integration. It is not part of the aweb product codebase.

### Optional services

Library, Tasks, Folio, profiles, blueprints, app integrations, A2A, and similar
services are optional extensions.

Library must not be required. A single-repository team must be complete without
installing Library or contacting it. Users who need managed profile sharing
across repositories may choose Library; users who do not need it should never
have to understand it.

An aweb communication identity is not the same thing as a soul definition.
Orchestrators may associate them, but soul reuse and soul storage remain outside
the communication core.

## Default journey

The target first-use journey is:

1. Install `aw`.
2. Establish a hosted or self-hosted communication scope.
3. Connect or provision two independently running agents without Library.
4. Send a durable message from one agent to the other.
5. Wake the intended recipient through an event integration.
6. Reply and wake the original sender.
7. Reconnect either runtime without losing durable state.
8. Understand how to continue hosted, across machines, or self-hosted.

Activation is the completed round trip, not account creation, team creation, an
identity record, or a package download.

## Target default `aw` concepts

The default product journey should expose only:

- connect or initialize;
- provision and retire communication identity;
- roster and status;
- send, inbox, and reply;
- events and watch;
- doctor and self-host.

Protocol administration, profiles, tasks, roles, locks, plugins, A2A, and
runtime management may remain supported and discoverable, but they do not
belong in the first-run explanation of the communication product.

These are target concepts, not a claim that the current CLI already presents
this exact surface.

## Hosting modes

Aweb remains open source and self-hostable.

The current self-hosted stack uses aweb, AWID, PostgreSQL, Redis, and Docker
Compose. Documentation must describe that honestly rather than presenting it as
an already frictionless embedded local relay.

The clean-user quickstart may ultimately use:

- a limited hosted communication scope;
- a genuinely bundled local relay;
- the existing operator-oriented self-hosted stack.

The chosen quickstart must have explicit trust, abuse, expiry, persistence, and
migration semantics. This SOT does not pretend an unimplemented local mode
already exists.

## Compatibility

Existing users and integrations matter.

- Shipped commands remain supported until a reviewed deprecation decision
  includes usage evidence and a migration path.
- Security, identity correctness, delivery reliability, production safety, and
  compatibility work continue during the product transition.
- Existing protocol and implementation SOTs remain authoritative for current
  behavior.
- The default surface may become narrower before advanced capabilities are
  removed.

No feature is retired merely because it is outside the initial wedge.

## Initial non-goals and paused directions

The initial product is not:

- Team Builder as the acquisition wedge;
- profile-first or blueprint-first onboarding;
- `aw team up` expansion;
- aweb-owned homes, worktrees, runtime launch, or session management;
- a required Library installation;
- a profile or app marketplace;
- a suite of first-party naapps;
- a generic dynamic gateway composition platform;
- a task tracker as the primary product;
- architecture decomposition justified only by a previous destination design.

Paused does not mean deleted. These directions can be reconsidered after the
communication wedge has real usage evidence.

## Measures

The activation measure is:

> Two independently running agents exchange a durable message, including
> recipient wake-up and reply delivery, without founder assistance.

Supporting evidence includes:

- decisions and elapsed time from install to the first round trip;
- successful reconnect without lost durable state;
- correct-recipient wake-up rate;
- idempotent provision and retirement;
- external orchestrator integration effort;
- recurring communication by external teams;
- cross-runtime and cross-machine use;
- support intervention required for activation;
- demand for optional services after communication already works.

## Authority and precedence

This document controls:

- what product is being built;
- which user and problem come first;
- product boundaries;
- prioritization;
- public positioning;
- target onboarding and default UX.

Current protocol and implementation SOTs control:

- shipped APIs and commands;
- identity and certificate semantics;
- routing, encryption, and delivery behavior;
- database and migration contracts;
- compatibility behavior.

The private cross-repository transition plan orders the work needed to move from
the current contracts to this target. It is an execution plan, not a public
protocol authority.

When documents disagree:

1. this product SOT wins for direction and priority;
2. the relevant protocol or implementation SOT wins for current shipped
   behavior;
3. a reviewed implementation change must update its governing contract;
4. historical or superseded product documents do not generate new work.
