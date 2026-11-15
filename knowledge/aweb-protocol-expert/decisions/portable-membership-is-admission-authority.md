---
type: Decision
title: Portable membership is admission authority, not a per-request gate
description: Portable signer membership evidence authorizes accepting one exact, complete signed certificate; accepted ordinary messaging is not gated on fetching custody provenance, the signer roster must also cover memberships accepted before custody, and an unavailable roster never authorizes a change, advances an accepted epoch or restores a withdrawn membership. Direction accepted (source-reported); not a design or implementation approval.
tags: [decision, membership, custody, admission, roster, availability]
timestamp: 2026-11-14
---

Accepted on 2026-11-14 as a direction decision. The admission, roster and
single-format judgment was delegated by the operator to an independent
reviewer and relayed by the OSS coordinator; the coordinator's final
reconciliation ruling followed agreement among three independent reviewers.
The harvester cannot read those records, so the acceptance is
**source-reported**. Message identifiers are omitted.

**Status:** direction only. Roster and epoch representations, stream guard
details and codecs remain under exact design review. Nothing here claims a
mechanism, an implementation or runtime behaviour.

# Decision

- **Admission binds the exact artifact.** Portable signer membership evidence
  authorizes accepting one exact, complete signed certificate. Admission binds
  the whole certificate's digest, not only its identifier.
- **New or changed artifacts need positive current authority.** A fresh
  admission, or any change to an accepted certificate, still requires
  positive, current custody or signer authority.
- **Accepted ordinary traffic is not a custody gate.** Once a certificate is
  accepted, ordinary messaging relies on that accepted membership and on the
  independent baseline checks (authentication, retirement, grants and
  revocation). It is not gated on fetching custody provenance per request.
- **The roster covers pre-entry memberships.** Signer-roster reconciliation
  must cover memberships that were accepted before the team entered custody.
  Otherwise a membership forged before entry would survive indefinitely.
- **An unavailable roster changes nothing in the attacker's favour.** Failing
  to obtain or apply the roster does not create a new refusal for accepted
  traffic, but it never authorizes a changed artifact, never advances an
  accepted epoch and never restores a membership already withdrawn. Immediate
  containment remains the explicit revoke or remove operation.
- **One statement format.** A single signed format serves roster, admission
  and approval statements. The actual human approver's opaque identifier is
  optional: unattended admission omits it, and it is never fabricated.
- **No custody outage extension.** Custody and admission authority get no
  outage allowance. An earlier architecture account that gave custody an
  extension of up to 900 seconds was an error and was explicitly corrected;
  the 900-second figure belongs only to the separate, pre-existing legacy
  ordinary-messaging outage allowance, measured from the original data age.

# Why

Stronger admission authority and ordinary use of an already accepted
credential are different assurances, and they fail differently. Checking
custody provenance at request rate makes provenance availability a way to
deny every legitimate existing member, without adding control an owner lacks:
revocation and removal already cut a member off at once. Binding the complete
digest at admission is what makes later acceptance safe without that gate,
and covering pre-entry memberships is what stops entry into custody from
grandfathering a forgery.

# Rejected

- **Request-rate custody enforcement** as a necessary security gate on
  ordinary accepted messaging, for the availability reason above.
- **Narrowing the decision to old registries.** The operator withdrew that
  scoping: registry-first rollout and treating a missing field as unavailable
  stand. No prerequisite of consumer memory that a team was ever in custody,
  and no signed custody-exit record, follows from this decision.

# Relation to other decisions

This applies [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md):
admission authority, current membership and baseline authentication are
separate inputs. As in
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md),
historical approval evidence does not stand in for current membership.

How fast reconciliation completes after a registry transition, and how a miss
is made visible, is a separate decision on the reconciliation target; this
concept does not restate it.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-boundary, 2026-11-14; notes/portable-membership-is-admission-authority.md.
