# Company-agent platform thesis

Status: working company strategy, 2026-07-30.

This document records the strategic conclusion that follows from the
communication-first product direction, the
[orchestrator evidence review](orchestrator-evidence-review.md), and the
specialization and learning model developed by
[OAS](https://github.com/OAS-Framework/oas). It does not redefine shipped
behavior or supersede the
[canonical aweb product SOT](aweb-product-sot.md).

Until evidence and a reviewed SOT change say otherwise, the communication
product retains its existing initial users, onboarding, public positioning, and
technical activation contract. The two-agent workflow below is the minimum
proof and design-partner pilot for the broader company-layer thesis, not a
replacement initial-product contract.

## Conclusion

The long-term vision is larger than agent messaging:

> Aweb should enable AI agents to become durable, trusted, learning
> participants in a company.

Communication and trust are necessary but not sufficient. An agent that is
part of a company must be able to:

- hold a stable identity and responsibility across sessions and runtimes;
- be reached by humans, agents, and company systems;
- receive work while offline and resume it after restart or succession;
- act under explicit, revocable authority;
- hand work to another responsible participant;
- retain role-specific expertise;
- propose durable learning from experience;
- inherit reviewed company knowledge and policy;
- leave evidence of what it did and why.

Aweb should not implement all of these concerns in its communication core.
The company vision is a composition of trust and communication, expert
specialization, and organizational governance.

## The minimum company-layer proof is two agents

One persistent agent can prove continuity and memory. It cannot prove
organization.

Two agents are the minimum at which the defining company behaviors appear:

- addressability across an independent boundary;
- delegation and handoff;
- distinct responsibilities;
- independent review or verification;
- escalation when the receiver cannot proceed;
- learning produced by one participant and reused by another;
- continuity when one runtime is unavailable or replaced.

The first company-layer pilot should therefore not be a fleet, an autonomous
company, or a blank team builder. It should be an opinionated pair of AI
coworkers completing one real workflow under human control.

The pair must have a reason to be two agents. Splitting one prompt arbitrarily
does not demonstrate organizational value. Good shapes include:

- researcher -> decision or execution specialist;
- implementation agent -> independent reviewer;
- support triage agent -> resolution specialist;
- lead researcher -> outreach drafter with a human approval gate;
- operations monitor -> incident investigator.

The company-layer pilot promise can be expressed as:

> Put two trusted AI coworkers on a real company workflow. They can reach each
> other, hand off work, survive restarts, and improve under review.

The first successful company-layer pilot ends with a useful company outcome,
not merely a delivered message. The durable message round trip remains the
communication product's prior technical activation event underneath it.

## Market hypothesis

Two potentially large groups may have immediate motivation:

1. CEOs and CTOs under pressure from boards, investors, employees, and peers to
   demonstrate useful adoption of AI.
2. Startup founders who believe agentic automation should let a small company
   operate with much greater leverage.

The hypothesis is that this urgency is common enough to create budget,
executive sponsorship, and a willingness to run pilots. It is not yet
validated, and even demonstrated urgency would not by itself be product-market
fit.

"We need an AI strategy" is often innovation theater. It produces demos,
internal announcements, and short-lived experiments without recurring use.
Founders can similarly enjoy building elaborate agent systems while avoiding
the customer, operational, or product constraint that matters.

The opportunity becomes real demand only when the urgency is attached to:

- an existing recurring workflow;
- a named accountable owner;
- a measurable baseline;
- an outcome the company already values;
- permission to integrate with the systems where the work happens;
- repeated use after the executive demo.

The initial validation motion for the company-layer thesis should therefore be
founder-led design partnerships, not a generic self-serve team creator. This
does not replace the communication product's current developer and
orchestrator-facing path. The design-partner offer is:

> Choose one workflow that matters. We will put two trusted AI coworkers on it
> and measure whether they create a durable operating advantage.

The executive mandate opens the door. The recurring result earns retention.

## Why OAS is a better organizational substrate

Gas Town organizes disposable coding workers around a task ledger and merge
pipeline. Paperclip organizes model invocations around an org chart, tickets,
and heartbeats. Both can generate activity and sometimes exceptional output,
but neither begins with the durable development of organizational capability.

OAS has a more promising model:

- a **soul** is a durable expert definition;
- an **instance** is one incarnation of that expert;
- a **session** is disposable runtime state;
- operating instructions, skills, and durable knowledge are reviewed artifacts;
- working instances capture experience;
- a separate harvest step judges whether learning should change future
  instances;
- messaging and tasks are integrations rather than the definition of the
  expert.

Its most important learning rule is:

> Promote only what is durable and would change what a future instance does.

This is materially better than treating transcripts as memory, retrieving
arbitrary historical text, or assuming that an agent with a corporate title has
acquired expertise.

OAS is nevertheless architecture, not market validation. As of this strategy
snapshot it is a newly public project with no public evidence of meaningful
external adoption. Its concepts reflect extensive internal operating
experience, but users have not shown that they will learn or configure the
system before receiving value. OAS is therefore a strong substrate and design
partner for aweb, not proof that the combined product has found a market.

## The required layer boundaries

The system should preserve three distinct responsibilities:

| Layer | Owns |
| --- | --- |
| Aweb and AWID | Trust, durable addressability, delivery, membership, delegation, revocation, and communication evidence |
| OAS | Expert definitions, instances, runtime composition, experience capture, role-specific skills, and soul learning |
| Company layer | Responsibilities, shared knowledge and policy, approval jurisdiction, evaluation, propagation, and organizational learning |

The hosted aweb.ai product may eventually present these layers as one coherent
company experience. That does not require collapsing them into one protocol,
repository, or authority.

In particular:

- aweb should not become a runtime launcher or agent-definition store;
- OAS should not become identity or communication authority;
- the company layer should consume aweb authority and OAS artifacts rather than
  create a second identity system or silently mutate experts.

## Two identity levels are required

The current composition gives an OAS instance a communication identity and
retires that identity with the instance. That is correct for attributing an
execution, but insufficient for a durable company participant.

A company agent needs two related identities:

| Identity | Purpose |
| --- | --- |
| Durable expert address | The continuing coworker or responsibility that humans and systems contact |
| Instance principal | The particular incarnation that received delegated authority and performed an action |

For example, `reviewer@acme.example` should remain reachable when one runtime
ends and another incarnation takes over. Messages, responsibility, and
relationship history belong to the durable expert. Keys, runtime authority,
presence, and action attribution belong to the active instance.

Succession must:

1. preserve the durable inbox and address;
2. bind a new instance explicitly;
3. delegate only the authority it needs;
4. revoke the retired instance;
5. record which instance actually acted;
6. deliver pending work without impersonating the predecessor.

This is a company-scale primitive that neither a simple inbox nor a reusable
agent profile provides alone.

## Learning must rise from instance to company

OAS provides a credible first loop:

```text
instance experience
  -> captured observation
  -> harvest judgment
  -> soul knowledge or skill
  -> future incarnation behaves differently
```

Company learning requires another governed promotion:

```text
soul learns something
  -> evidence and provenance remain attached
  -> authorized reviewer decides jurisdiction
  -> company knowledge, policy, skill, or evaluation changes
  -> affected experts receive a versioned update
  -> later outcomes test whether the change helped
  -> rollback remains possible
```

Not every lesson should spread. A repository-specific build workaround belongs
to one engineering expert. Product terminology may bind the whole company. A
legal policy may constrain several teams while remaining unreadable to others.

Company learning therefore needs:

- provenance back to the work that produced the proposal;
- explicit jurisdiction and access control;
- review by a human or authorized coordinator;
- conflict resolution when experts learn incompatible things;
- versioning, staged propagation, and rollback;
- evaluations tied to later behavior and outcomes.

This is organizational learning, not a larger memory store.

## Organization is not an org chart

The system must not copy Paperclip's assumption that corporate appearance
creates corporate behavior.

Organization consists of:

- durable responsibility;
- discoverable capabilities;
- interfaces between responsibilities;
- authority and approval boundaries;
- expected handoffs;
- escalation paths;
- accountability for outcomes;
- succession;
- reviewed propagation of learning.

Reporting relationships may be useful projections for humans. They are not the
primary coordination primitive. The first two-agent workflow should make the
responsibility boundary and handoff explicit without requiring a synthetic
executive hierarchy.

## Company-layer pilot discipline

The vision must not recreate the previous team-builder strategy. The initial
design-partner offer should have:

- one important workflow, not an empty organization;
- two preconfigured responsibilities, not a role editor;
- integration with real company systems;
- a human owner and approval boundary;
- a before-and-after measure;
- concierge setup while the pattern is still being learned;
- a path to paid use before broad platform construction.

Do not build for the company-layer pilot:

- a catalogue of elaborate agent companies;
- a drag-and-drop org chart;
- generic autonomous-company claims;
- a large company knowledge portal;
- another task tracker;
- activity metrics that reward messages, agent count, tokens, or heartbeats.

The infrastructure should generalize. The customer experience should be
specific.

## Validation program

Recruit CEOs, CTOs, and founders who have both executive urgency and a real
workflow. Prefer an imperfect process already consuming human time over a new
process invented for the pilot.

For each design partner:

1. Select one recurring workflow with two genuinely distinct responsibilities.
2. Record the current human time, elapsed time, failure rate, and accepted
   output.
3. Install the two-agent workflow with aweb communication and explicit human
   authority.
4. Run repeated real cycles for at least four weeks.
5. Force at least one runtime restart or instance succession.
6. Review at least one learning proposal.
7. Observe whether a later cycle actually reuses the approved learning.
8. Ask the customer to pay for continued operation.

Evidence of value is:

- the workflow is voluntarily used again;
- useful outcomes are accepted by the responsible human;
- handoffs complete without the human acting as message bus;
- restart or succession does not lose responsibility or work;
- human supervision and recovery effort decline;
- approved learning changes later behavior;
- the customer wants another workflow or more capacity.

Evidence against the thesis is:

- the system is used only for the executive demonstration;
- the customer prefers one direct model session;
- the two agents create review or coordination work without better outcomes;
- learning is captured but never reused;
- every cycle requires founder intervention;
- the customer will not pay after the pilot.

## Strategic sequence

The sequence should be:

1. Keep aweb's communication-first core and integration contract narrow.
2. Make OAS the best first proof of durable expert specialization over aweb.
3. Correct the durable-expert versus instance-principal identity model.
4. Deliver one opinionated two-agent company workflow with a design partner.
5. Prove recurring work, succession, and one reviewed learning loop.
6. Repeat the pattern across several unrelated customers.
7. Productize the shared company governance and learning surface only after the
   repeated workflows reveal what is common.

The durable strategic statement is:

> Aweb is the trust and communication foundation for AI coworkers. With an
> organizational substrate such as OAS, it enables specialized agents to hold
> responsibility, work together, survive succession, and learn under company
> control.

The vision is company-scale. The proof begins with two agents and one outcome.
