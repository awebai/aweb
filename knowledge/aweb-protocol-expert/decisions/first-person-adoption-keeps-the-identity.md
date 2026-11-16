---
type: Decision
title: First person adoption keeps the agent's identity
description: An agent certified directly under its organisation namespace may acquire its first person parent once, keeping its ID and key, because that adds responsibility without moving it between people; recreating the agent was rejected. It is not permission to move an existing person or agent parent. Adopted model (source-reported); contract on main, implementation not yet landed.
tags: [decision, identity, id-certificates, adoption, responsibility]
timestamp: 2026-11-16
---

**Status:** an operator-adopted model, source-reported on 2026-11-16. The
normative contract is on main in `docs/id-certificates.md` §2 and §6 ("First
adoption under a person"). The implementation was still in review and
unreleased when this was recorded. This concept keeps the rationale; the
contract is the authority for the rule's exact terms.

# Decision

A local key otherwise keeps one parent for its lifetime. The single exception:
an agent whose certificate is signed directly by its organisation's namespace
may acquire its **first** person parent, once, keeping the same ID and key. The
person signs explicitly for that named agent and key. A chain that already
contains a person, or an agent whose parent is another agent, does not
qualify. This is not permission to move an existing person or agent parent.

The case is permanent, not a one-off migration: it recurs whenever someone
creates agents first and claims their human afterwards.

# Why it is safe to keep the old certificate

The retained namespace certificate carries no human responsibility. Presenting
it reports `no_human`, just as a chainless presentation reports `unknown`.
Holding it gives no power to move responsibility from one person to another,
so keeping it valid alongside the new person-parented chain opens no transfer
path. That is the limit of the exception: it only ever goes from no person to
a first person.

The accepted local limit follows from this. The old local certificate stays
cryptographically valid and keeps reporting `no_human`, and existing
descendants report `no_human` until their carried ancestry is refreshed.

# Rejected

**Recreate the agent under the person.** Rejected because it throws away a
working identity, its memberships and its mailbox to repair a responsibility
property that the original creation path never supplied. Do not reintroduce
recreation as a prerequisite for adding the first human.

# Relations

This complements, and does not supersede,
[owner binding needs independent authorities](owner-binding-needs-independent-authorities.md):
responsibility ancestry still supplies neither custody nor human-session,
membership or action authority.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-person-parent,
2026-11-16; notes/first-person-adoption-keeps-identity.md.

Acceptance is **source-reported**: the source reports the operator adopted the
model on 2026-11-16 and that the O1 exception was clarified the same day, both
relayed through coordinator mail. The harvester could not read that mail, so
this is neither verified nor the operator's own words. The contract text
landed on main at 44ae69258; the implementation candidate 60bd2796d (task
aweb-adel) was not on main at harvest.
