---
type: Lesson
title: A grant on a set someone else governs hands them the widening decision
description: When a grant's subject is a set of principals, ask who can grow the set; if that is not the resource owner, the grant lets that party widen use without the owner's confirmation. In aweb secrets, a grant on an inheritance policy lets the team controller widen secret use with no owner passkey; naming the eligible root with an owner-set depth bound keeps every widening behind the owner.
tags: [lesson, secrets, grants, authorization, trust-model, inheritance]
timestamp: 2026-11-10
---

A resource grant whose subject is a dynamic set ("every member admitted under
team policy P", a role, a subtree) covers whoever is in that set later, not
only whoever is in it now. Whoever governs membership of the set therefore
decides, after the grant, who gains use of the resource. If that party is not
the resource owner, the grant has moved the owner's widening decision to them.
Each piece can look sound on its own: the grant was owner-confirmed, and the
set change was authorised by its own governor.

# How it shows up in aweb secrets

Secrets requires owner passkey confirmation for every widening change,
granting included (`docs/design/secrets.md` §6.3).
For workers inherited into a team, the convenient subject is the inheritance
policy. But the policy's eligibility set belongs to the team controller, who
can grow it with a named-parent eligibility grant or the all-direct-members
mode. A policy-scoped secrets grant would let the controller extend secret use
to more members with no secrets owner passkey.

This is a second path, separate from the controller power that secrets §14.1
already records as T10, where a controller that re-certifies an existing
`did:aw` inherits its grants. Policy-scoped eligibility needs no
re-certification.

The design proposal for aweb-acwd.16 (`docs/design/secrets-inherited-member-grants.md`,
at 5126651c7 on a review branch, not on main) therefore recommends a
root-scoped subject (`policy_id`, `root`, `max_depth`). It names the eligible
direct member that starts a line, and it bounds depth with the owner's own
`max_depth`, so a controller-raised policy depth does not extend use. The cost
is one owner act per root, never one per worker. The design presents the
policy-scoped subject as the alternative, with this cost stated.

**Status:** this is a proposal under review, and the operator has not ruled
on it. This lesson does not record the choice of subject as decided. The rule
below holds whichever subject is chosen.

# How to apply

- For any grant or policy over a dynamic set, name the party that can grow the
  set. If it is not the resource owner, the subject bypasses the owner's
  confirmation rule, so choose a subject the owner controls instead.
- Prefer a subject anchored on an owner-chosen principal (for example the
  root of a line) plus an owner-set bound, over the most convenient set
  identifier.
- If a governed-set subject is still offered, state the bypass as its cost in
  the design, so the owner accepts it knowingly.

Related: [owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md),
[team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/grant-subject-must-not-follow-controller-eligibility.md.
Checked by the harvester: secrets §6.3 and T10 (§14.1) on main 38f95eafd,
and the root- and policy-scoped subjects and their stated cost in the design
proposal at 5126651c7.
