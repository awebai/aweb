---
type: Lesson
title: Local stop is not new binding authority
description: Preserve an existing account-owned stop after membership loss under its session and exact-owner checks; creating a binding and stopping one have different powers, and portable signed unbind keeps its own contract. The same rule binds every narrowing act, so a controller-signed revoke of a role holding needs only its authority and never the holder's current membership, kind or registry answer.
tags: [lesson, authority, human-channels, revocation, membership]
timestamp: 2026-11-08
---

Applying the full current-owner gate to every binding mutation appeared
consistent, but would also prevent a departed member from stopping an existing
personal delivery binding. Consumer review of aweb-acmj.19 identified that
broken neighboring journey before implementation.

# How to apply

- Classify the effect before reusing its policy. Creating or rebinding grants
  authority; stopping one's exact existing delivery path reduces it.
- Preserve the existing account-owned stop with its actual session, request
  protections and locked exact-owner checks after membership loss. Reuse that
  operation rather than inventing a second stop API.
- Keep the scope narrow: no transfer, restored delivery, new ownership proof or
  access to another account's binding follows from a local stop. Portable
  signed unbind still requires its own signer, proof and current-rights policy.
- Pair the refusal with its valid neighbor: a removed member cannot create a
  binding, but can stop their own existing one; another account cannot stop it.

# Narrowing acts need only their authority

The same split holds when the narrowing act is not the holder's own. A
controller-signed revoke of a role holding targets the stored binding and
needs only the controller's authority over it.

- It must not require the holder's current membership, its subject kind, or
  a registry answer about the holder. Otherwise a departed holder, or one
  whose registry is unreachable, can never be retired, and the act meant to
  remove authority is blocked by the very loss it responds to.
- Eligibility checks belong to designation, replacement and use. A revoked
  holding cannot be used, so the eligibility check guards nothing at revoke
  time.
- The rule recurs across owner acts, grants and memberships. When writing
  any revoke, retire or unbind act, write the departed-holder and
  unreachable-registry cases as tests; they are the elimination route.

This was found in review of an otherwise ACKed owner-act proposal (a revoke
gated by the holder's membership) and fixed before ACK. That proposal awaits
the operator's rulings; only the rule is recorded here.

This refines [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md):
one policy per operation does not mean one predicate for effects with different
powers. See the [owner-binding decision](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
for positive authority; neither rule should silently replace the other.

# Provenance

Manual harvest on 2026-10-29 from `aweb-protocol-expert-acmj-binding`, note
`local-stop-is-not-new-binding-authority.md`, task aweb-acmj.19. The rejected
blanket gate and retained reducing control are captured by
`docs/human-channel-binding.md:166–205` at
`053ff87bd6f8834fe19df614438a5eaeec71341a`. The accepted design records the
boundary; this lesson does not claim a new runtime or race-test result.

The section on narrowing acts: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/designation-act-binds-the-credential.md.
