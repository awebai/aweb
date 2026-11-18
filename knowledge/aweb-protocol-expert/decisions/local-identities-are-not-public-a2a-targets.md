---
type: Decision
title: Local identities cannot be public A2A targets
description: An A2A bridge route is a public entry point and must target a global identity with a real assigned address; configuration resolves the target's actual identity and refuses local scope, including through aliases or another identity's address label, because local is an isolation choice that keeps externally injected prompts out of a private team member. Ruled; implementation pending.
tags: [decision, identity, a2a, bridge, local-identity, isolation]
timestamp: 2026-11-18
---

Ruled by the operator on 2026-11-17 as an isolation rule. The acceptance is
**source-reported**: the coordinator relayed the ruling to the source by mail
on 2026-11-18 and withdrew an earlier request for a successful local-target A2A
journey. The harvester could not read the relay or the original ruling, so
nothing here is verified or quoted as the operator's words.

**Status (2026-11-18):** ruled. The implementation and a real managed-runtime
journey are in progress. No successful local-target runtime result and no
release is claimed.

# Decision

- A local identity is an isolation choice, not an unfinished global identity.
  An A2A route is a public entry point, so its target must be a global identity
  with an actual assigned public address.
- Bridge configuration resolves the target's real identity and refuses when it
  is local. The refusal explains the public-address and team-isolation reason
  and the supported alternative: target a global addressed identity.
- Nothing address-shaped grants a local member outside reachability: not a
  namespace/member display label, not another identity's address, and not an
  alias that resolves to a local member.
- The exception that lets a local agent receive replies in a conversation it
  started does not open a public A2A door to that agent.

The positive neighbour of this rule is a bridge to a global addressed target;
the local neighbour is a configuration refusal, not a successful journey.

# Rejected

- **Repairing the missing address**, by fabricating or assigning one so the
  bridge can proceed. An addressless local identity is not a setup defect: an
  invented address undoes the operator's isolation policy.
- **A new or implicit local-target selector** for bridges. It would let
  external prompts reach a private team member through a door the operator
  chose not to have.

A future request for a bridge to local members must surface this decision for
a ruling instead of inferring new authority from configuration.

# Relation to other concepts

This adds the isolation rationale to
[gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md):
target authority is decided at configuration and admission, before any
delivery. It supersedes nothing. The public contract already says a local
identity has a member name, no address and no global first-contact address
(`docs/identity.md`, "Name and address rules"; `docs/identity-messaging-contract.md`,
"Global And Local Identities" and the cross-team local receive rules); this
decision records why that boundary also holds for A2A bridges.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-a2a,
2026-11-18; notes/local-identities-are-not-public-a2a-targets.md. Contract
support checked at aweb main 1277041b2b8b; that is contract evidence, not
implementation or release evidence.
