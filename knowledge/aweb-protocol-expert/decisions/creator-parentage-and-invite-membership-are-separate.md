---
type: Decision
title: Creator parentage and invite membership are separate authorities
description: The creator of an agent signs its parentage and an invite authorizes only membership, optionally conditioned on the joiner's verified nearest human; joining never reparents an existing identity, and an invite that creates a fresh identity keeps its issuer as creator. Operator-adopted target, not yet implemented.
tags: [decision, identity, parentage, invites, membership, teams, authorization]
timestamp: 2026-11-16
---

**Status:** an operator-adopted target model, source-reported on 2026-11-16
through the OSS coordinator after protocol-owner discussion. It is not
implemented and its wire shape is neither designed nor approved; the current
behaviour still pins parentage to the invite issuer. Implementation is
assigned as task aweb-adej. This concept records the decision, not runtime
behaviour.

# Decision

Two questions get two independent authorities:

- **Who created the agent** decides its parentage. The creator signs the
  child's ID certificate. Creation can take a parent source independently of
  any invite.
- **Which team it may join** is what an invite authorizes. An invite carries a
  membership condition on the joiner's verified nearest human:
  - by default, the issuer's verified nearest human; an issuer with no
    verified human sets no condition;
  - an explicitly selected other human requires the joiner's own verified
    chain to that person, and the issuer then signs no parentage.

Joining never changes an already-established parent. When an invite creates a
fresh identity and no parent was selected independently, the invite's issuer
is the creator and signs the child link, so today's fresh-identity joins,
cross-machine joins included, keep working.

The team grant stays a separate team certificate under controller authority
([team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md)).
The membership condition signs no ID link, does not broaden registry add or
revoke authority, and adds no inviter column.

# Why

Neither a team credential nor possession of an invite establishes the
authority to change who answers for an agent. Making the invite issuer the
parent stops an agent of one person from joining another person's team without
changing who is responsible for it. Dropping attribution on an invite from an
attributed issuer would instead admit agents without the responsibility that
issuer already carries. Two independent inputs avoid both outcomes.

# Rejected

- **The invite issuer always signs parentage.** It couples membership to
  responsibility and forces reparenting to join a team.
- **Invites carry no human condition.** It admits unattributed agents through
  an attributed issuer.

# Constraints and open questions

Existing identities are not changed, and released clients remain a constraint
([released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)).
Unresolved and not ruled here: whether existing organisation-parented
identities may ever be reparented, and whether the admission condition is
rechecked after an invite is accepted.

The decision is consistent with the original-principal rule in
[one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md),
and, like [owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md),
treats a verified nearest human as one input, not as authority over identity.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-16; notes/creator-parentage-and-invite-human-condition.md.
Acceptance is source-reported (the operator's adoption, relayed by the
coordinator in mail the harvester could not read), not verified.
