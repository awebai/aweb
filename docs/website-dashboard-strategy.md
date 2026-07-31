# Aweb website and dashboard strategy

Status: working product strategy.

This document translates the target product contract in
[aweb-product-sot.md](aweb-product-sot.md) into a public website, documentation
journey, and hosted dashboard. It does not redefine shipped behavior or commit
the product to a specific third-party integration.

## Strategic rule

The public product must make sense without reference to any particular
orchestrator.

Aweb should not present itself as an accessory to Paperclip, Gas Town, OAS, or
any other named system. Their adoption and productivity are unproven, their
product shapes may change, and some may never become durable ways of working.
Borrowing their language would make aweb harder to understand and would tie its
credibility to theirs.

Named systems belong on integration pages only after there is a maintained,
working integration and evidence that its users obtain value from it. They are
distribution channels and compatibility examples, not the definition of aweb.

The durable category is:

> Communication infrastructure for independently running agents.

The durable product promise is:

> Your agents need an inbox. Stop being their message bus.

## What a visitor must understand

Within roughly thirty seconds, a technically literate visitor should understand:

1. Their agent processes can have stable, addressable inboxes.
2. A message remains available while its recipient is offline or restarting.
3. Delivery can wake the correct recipient and produce an acknowledgement or
   reply.
4. This works across sessions, runtimes, machines, and independently operated
   systems.
5. Aweb is not an orchestrator: it does not decide tasks, create worktrees,
   choose models, or manage the agent's reasoning loop.
6. They can use a maintained adapter or implement a small integration contract.
7. The hosted dashboard lets them see whether communication actually worked.
8. The core is open source and self-hostable.

If the page instead leads with teams, roles, blueprints, tasks, fleets, or a
catalogue of agent runtimes, it recreates the ambiguity of the current product.

## Homepage

### Hero

The hero should describe the invariant problem rather than a fashionable
workflow.

Suggested structure:

- Eyebrow: **Communication infrastructure for agent systems**
- Headline: **Your agents need an inbox.**
- Supporting copy: **Give independently running agents durable addresses,
  messages, and wake-up events across sessions, runtimes, and machines.**
- Primary action: **Connect two agents**
- Secondary action: **Integrate your system**
- Technical action: **View the source**

The phrase **Stop being their message bus** is useful supporting language because
it names a real operator burden. It should not imply that aweb itself schedules
or supervises work.

### Show the transaction

The first proof should be a real, compact message round trip:

```text
sender accepted
message stored
recipient connected
wake requested
wake accepted
message acknowledged
reply delivered
```

The example should include a restart or offline interval. A generic architecture
diagram or simulated chat transcript does not demonstrate the hard part.

Until this trace comes from a repeatable external integration, label it as a
product contract or technical demonstration rather than customer proof.

### Explain the boundary

The homepage should include a short contrast:

| Your system owns | Aweb owns |
| --- | --- |
| agents and prompts | stable communication addresses |
| tasks and scheduling | durable message delivery |
| models and runtimes | reconnect and replay |
| workspaces and tools | acknowledgements and replies |
| reasoning and supervision | wake-up events and delivery evidence |

This boundary is more important than a long feature list. It lets an
orchestrator author see that integration does not surrender control of their
product.

### Route the two users

After the proof, split the journey:

- **I run agents:** connect two existing agent processes and complete a durable
  round trip.
- **I build agent infrastructure:** provision addresses, consume delivery
  events, acknowledge messages, and retire identities.

Integration cards may appear below this split. A card must state its maturity
honestly: experimental, maintained, community, or reference. Do not feature a
logo merely because an integration is conceivable.

## Integration pages

Each real integration receives a dedicated page. The page should answer:

- What concrete problem does this adapter solve?
- What object in the external system receives an aweb address?
- What process consumes inbound events?
- What exactly happens when a message arrives?
- Who or what may be awakened?
- How are unknown senders, untrusted content, and duplicate delivery handled?
- What data and permissions does the adapter need?
- How does the operator see a failed delivery and retry it?
- How are addresses retired and the integration removed?
- Is the integration maintained by aweb, upstream, or the community?

The page should contain a short install path, a real round-trip trace, source
code, security behavior, troubleshooting, and uninstall instructions.

No named integration should enter the homepage headline or define the product
category. The strongest integrations can appear later as evidence that the
generic contract works in different environments.

## Documentation

The documentation should follow the product journey rather than the current
implementation taxonomy.

### Quickstarts

1. Connect two agent processes.
2. Integrate an orchestrator.
3. Use a maintained adapter.
4. Self-host the communication service.

Every quickstart should end with the same observable result: delivery, wake,
acknowledgement, and reply visible in the dashboard or CLI.

### Core concepts

- addresses and ownership;
- messages and threads;
- delivery events;
- reconnect, replay, and acknowledgement;
- wake adapters;
- provisioning and retirement;
- trust, encryption, and sender provenance.

### Integration contract

The smallest useful conceptual interface is:

```text
provision(address)
send(message)
watch(cursor) -> event
ack(event)
retire(address)
```

The actual API and SDKs must document idempotency, cursors, ordering, delivery
guarantees, retries, errors, and lifecycle behavior. This sketch is positioning,
not a claim about the current wire API.

Profiles, blueprints, tasks, roles, locks, team launch, Library, and A2A remain
available as compatibility or advanced material. They should not precede the
first successful exchange.

## Hosted dashboard

The dashboard is an operational delivery console, not an AI workforce control
room.

Its primary navigation should converge on:

- **Overview**
- **Integrations**
- **Addresses**
- **Deliveries**
- **Settings**

Organizations remain useful for access and billing, but should not be the
product's central visible resource. Teams, profiles, roles, tasks, and agent
launch controls should leave the primary navigation unless later usage evidence
establishes a separate product demand.

### Empty state

The first screen should say **Connect your first agent system**, then offer:

- a generic integration path;
- any genuinely maintained adapters;
- a self-hosted path.

Activation progress should reflect a real transaction:

```text
integration connected
address provisioned
event consumer online
test message delivered
recipient awakened
reply received
```

The product should celebrate the first independent agent-to-agent round trip,
not organization creation, namespace allocation, or identity issuance.

### Activated overview

The overview should answer whether the communication system is healthy:

- connected integrations;
- reachable addresses;
- recent delivery success;
- pending and quarantined messages;
- wake success and latency;
- recent round trips and failures.

### Integration detail

Show:

- adapter and version;
- external-system-to-address mapping;
- current event cursor and consumer health;
- last successful delivery and wake;
- permissions and sender policy;
- quarantine and allowlist configuration;
- a safe test-message action;
- disconnect and retirement behavior.

### Address detail

Show the address, owning connection, lifecycle state, last seen time, allowed
senders, wake adapter, and health. DID, certificate, key, and namespace details
belong under an advanced or trust view.

### Delivery detail

The delivery record is the heart of the product. It should show:

- verified sender and intended recipient;
- message and thread identifiers;
- acceptance and durable-storage time;
- delivery attempts;
- disconnect and replay events;
- wake request and result;
- acknowledgement and reply;
- failure reason, retry state, and latency.

For end-to-end encrypted content, the dashboard should show operational metadata
without implying that the hosted service can read message contents.

## Signup and pricing

Signup should preserve the visitor's intent. Someone arriving from an adapter or
integration guide should land in the matching setup flow after account creation,
not in a generic organization wizard.

Initial pricing language should be simple and factual:

> Open source and self-hostable. Hosted relay free for development.

Pricing can later follow demonstrated value such as active addresses, retained
delivery history, message volume, private networks, or enterprise controls.
Vague team tiers would pull the product back toward the category it is leaving.

## Evidence gates

The surface must distinguish technical proof from market proof:

- **Technical proof:** two independent runtimes complete the defined round trip
  repeatedly, including restart and replay.
- **Integration proof:** an external maintainer can add aweb without founder
  intervention and keep the adapter working.
- **User proof:** an operator chooses to keep the integration enabled and uses it
  for recurring work.
- **Market proof:** several unrelated users exhibit the same behavior and seek
  greater reliability, volume, or control.

Repository stars, launch attention, agent-count claims, impressive demos, and
theoretical compatibility do not pass these gates.

## Recommended rollout

1. Make one generic two-agent round trip repeatable.
2. Make one external adapter complete the same round trip.
3. Publish the delivery trace and the exact product boundary.
4. Replace the homepage positioning.
5. Reorder the docs around first exchange and integration.
6. Replace the dashboard empty state and primary navigation.
7. Build delivery and integration diagnostics.
8. Move legacy team-management surfaces out of the default journey.
9. Revisit pricing only after recurring external use.

The governing principle is:

> The website explains why independent agents need aweb. The dashboard proves
> that aweb delivered.
