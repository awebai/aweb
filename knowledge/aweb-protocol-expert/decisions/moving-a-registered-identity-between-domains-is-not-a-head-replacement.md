---
type: Decision
title: Moving a registered identity between domains is not a head replacement
description: A local namespace-only agent may take its first person parent in another domain, but a registered identity cannot change domain by replacing its head in one tree or by sequential supersede-then-register calls; that needs a separately designed atomic migration between two registry trees. Reviewer disposition source-reported; contract on main, migration not designed.
tags: [decision, identity, id-certificates, adoption, domains, registry]
timestamp: 2026-11-16
---

**Status:** a reviewer disposition, source-reported on 2026-11-16. The supported
behaviour is on main in `docs/id-certificates.md` §6 ("First adoption under a
person"): registered adoption requires the person's home domain to equal the
agent's domain, and a local agent may request its first person in another
domain. This concept keeps the reasons and the rejected workaround, which the
contract does not state. The registry migration is tracked as aweb-adeq; no
migration design, implementation or authorization exists.

# Decision

A person has one home domain, which need not be the namespace of a team they
join. First person adoption may therefore cross domains for a **local**
namespace-only agent, but not for a **registered** one. A registered identity
changes domain only through a cross-domain registry operation that does not
exist yet. That operation must define, as one atomic act:

- retirement of the old tree's live head, so the ID is never valid in both
  trees at once;
- what happens to descendants still certified in the old domain;
- how revocation works in either tree afterwards.

# Why the local exception is safe and the registered case is not

The local exception is safe because the old namespace certificate carries no
person and can never be revoked: it already reports `no_human`, so leaving it
valid beside the new person-parented chain removes no person's responsibility
and moves none between people. Its cost is the descendants. Their fixed
old-domain certificates cannot be joined to the parent's new domain by the
ordinary re-sign exchange, so they keep reporting `no_human` and must be
respawned under the adopted parent.

A registered identity is different because two registries are involved. A
valid human signature and an expected-head comparison settle authority inside
one tree only. Neither one serializes the other tree, so neither can make
retirement in one domain and enrolment in the other a single act.

# Rejected

**Sequential supersede in the old domain, then register in the new one.**
Between or after the two calls the same ID can be valid in both trees, and
which human is responsible would depend on which domain a verifier asks. A
partial failure leaves that state indefinitely. Do not implement registered
cross-domain adoption by chaining existing calls; the `domain_mismatch` refusal
on the registered path is deliberate, not a missing case to work around.

# Relations

This refines the first person adoption rationale (same ID and key, adopt once)
and does not relax
[owner binding needs independent authorities](owner-binding-needs-independent-authorities.md):
responsibility, custody and membership stay independent, so a domain move of
responsibility ancestry would carry no custody or membership with it.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-person-parent,
2026-11-16; notes/domain-move-is-not-head-replacement.md.

The reviewer's disposition and the operator's approval of the local exception
are **source-reported**: they were relayed through coordinator mail that the
harvester could not read, so they are neither verified nor anyone's own words.
The source reports that a real registered cross-domain request was refused
with `domain_mismatch`, and that paired `aw` controls later passed local
cross-domain first adoption and registered same-domain replacement. The
harvester did not rerun these controls. The contract text is on main at
332f9887d.
