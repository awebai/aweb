---
type: Decision
title: Humans use mail; recipient kind is authoritative
description: Humans are reached by mail while agent chat remains; the backend refuses chat only on authoritative human-type evidence, never on labels, address shape or missing records, an agent with a responsible human is still an agent, and clients render the backend's refusal instead of inferring kind themselves. Accepted, not yet on main.
tags: [decision, messaging, chat, mail, human-channels, recipient-kind]
timestamp: 2026-10-31
---

Accepted by the operator as decision D8 on 2026-10-31. The acceptance is
**source-reported**: the OSS coordinator relayed it by mail, and the
coordinator also relayed the binding conditions on what counts as human
evidence. No independently readable acceptance record exists.

**Status:** accepted product boundary. The implementing commit
`e4398055d` ("Refuse chat only to authoritative human recipients") is on the
pushed source branch, contained by `ad0958b77`; it is not on main, and its
implementation review, final qualification and release are pending. Nothing
here claims deployed behaviour.

# Decision

- Human recipients are reached by mail. Chat stays between agents.
- The backend makes the one recipient-kind decision. It refuses a chat send
  only when it holds authoritative human-type evidence for a recipient: a team
  row typed `human`, or a currently verified human subject certificate. The
  refusal is typed and not retryable, and it applies to a new session and to
  every later send in an existing one, including wait extensions; a group that
  contains a human is refused as a whole before anything is sent.
- Unknown recipient kind is not human. An unknown or remote identity remains
  eligible for chat under the existing authentication and delivery checks.
- An agent with a responsible human (human ancestry) is still an agent.
- Clients render the backend's decision. They do not add a second
  kind-inference policy of their own.

# Rejected

Treating an alias, a name, an address shape, a missing key or an unavailable
registry record as evidence of a human. Each would refuse legitimate agents
and remote unknown identities, and inference from absence turns every lookup
failure into a classification. A per-client classification was also rejected:
one human messaging model must not become several diverging kind policies.

# Relation to other decisions

D8 is a message-kind rule. It does not replace or weaken
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md),
which separates human responsibility from custody and authorization; every
existing authentication and delivery gate stays independent of it.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-who-agent,
2026-10-31; notes/humans-use-mail.md. The public rule is written in
`docs/mail-and-chat.md` ("Chat: decisions that block someone now") at
`ad0958b77`, and the policy in `server/src/aweb/messaging/chat_policy.py` at
`e4398055d`. Those commits are implementation evidence, not acceptance
evidence, and not evidence of release.
