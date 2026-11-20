---
type: Decision
title: Public human identity is opaque; names are domain-controlled disclosure
description: A human appears in anything aweb publishes only as an opaque identifier under its domain, never as a name, email or other contact; the rule binds every publication producer and linked label, not only the identity certificate, and the domain alone decides to whom it discloses the person's name. Direction accepted; authorizes no migration, narrowing or registry/DNS write.
tags: [decision, identity, privacy, registry, publication, humans]
timestamp: 2026-11-14
---

Accepted by the operator as a direction decision on 2026-11-14. The
acceptance is **source-reported**: the OSS coordinator relayed it to the
source, and no independently readable acceptance record exists.

**Status:** direction only. Nothing here claims a mechanism, an
implementation, a migration or deployed behaviour.

# Decision

- A public human record carries an opaque identifier under the domain. It
  carries no personal name, email address or other contact detail.
- The rule binds every producer of public material, not only the signed
  identity certificate's field whitelist. An opaque identifier does not
  discharge the decision if a producer copies the person's login or name into
  a public namespace label, an address handle, a membership label or any other
  label linked to that identifier.
- Naming is domain-authorized private disclosure, separate from public
  verification. The domain decides to whom it discloses the person's name.
  Authorization and ancestry stay publicly verifiable without it.
- Opaque does not mean unlinkable. The permitted identifier is stable, and
  nothing here promises that two uses of it cannot be linked.
- Exact-reference lookup is a discovery bound, not a privacy boundary.
  Requiring the caller to know an exact reference does not make personal
  fields returned by that lookup private, so they must not be returned.

# Why

Identity must stay independently verifiable in the open, but the registry
must not become a public directory of people's personal details. Keeping
authorization and ancestry verifiable while the friendly-name mapping stays
under the domain's control gives both. An audit showed the gap this decision
closes: an opaque certificate can sit beside public labels that name the
person, so judging privacy by the certificate's fields alone would rebuild a
named directory around an opaque identifier.

# Rejected

Treating the opaque certificate as sufficient while surrounding publications
carry names, and treating exact-reference lookup as permission to return
personal fields.

# Limits

This is a direction, not authority for change. It does not authorize
narrowing released verifiers, rewriting existing signed artifacts, a
migration, or registry or DNS writes. A migration needs its own reviewed
decision, and
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
binds it.

# Relation to other decisions

[Owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
already rejects email or alias equality as evidence of a human action; this
decision keeps such personal details out of public material altogether.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes,
2026-11-14; notes/opaque-human-publication-decision.md. The source's audit,
read-only at aweb ae3a47aa6982, separated opaque certificate fields from
linked publication labels; its code observations are not recorded here.
