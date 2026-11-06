---
type: Decision
title: Review blocks only on realistic failures
description: In the naapp and integrations lanes a review blocks a landing only on a realistic, supported-behaviour failure; a behavioural RED on released code is sufficient proof, speculative hardening is a non-blocking note, and full feature scope still stands.
tags: [decision, review, scope, naapps]
timestamp: 2026-10-23
---

Review practice of the naapp lanes, set by the naapps coordinator relaying the
operator's direction on 2026-10-20 and tightened on 2026-10-23, and carried as
standing review rules by the integrations lane. The OSS coordinator confirmed on
2026-10-25 that it has no record of this as team-wide doctrine: apply it where
those lanes' instructions apply, not as a general rule. The 2026-10-20 direction
rested on the naapp surfaces having no deployed consumers yet, so review depth
followed actual exposure; revisit the bar when exposure changes.

The trigger was review churn. A reviewer held a release for a lock cycle that
needed a host callback policy neither supported host had, and asked for further
diagnostic rounds after a behavioural RED had already shown the reported
failure. The ruling for that case was a contract line in the docs, no
reproduction and no code.

# Decision

- A review blocks only on a realistic failure: an unauthorized action, data
  exposure, lost or duplicated writes, a crash on real input, broken or
  confusing UX, or behaviour that violates the contract.
- Theoretical hardening (clock skew between workers, growth caps, rare races
  with no realistic trigger, a cycle no supported host can reach) is a
  non-blocking note. Do not demand a reproduction or an implementation
  expansion for it.
- A RED counts when it shows the reported user-visible failure on released
  code. Do not require internal-mechanism proof as a second gate; keep causal
  claims qualified instead.
- A test-only or docs-only delta on an ACKed head carries the ACK, but test
  changes still get an independent read, because they change what a green
  result proves.
- One reviewer reply per request: verdicts go to the author, and authors mail
  the coordinator only for landing requests, rulings and unresolved blockers.
- Review depth changes, scope does not: every specified feature stays, and
  proof effort moves to real flows and UX.

# Rejected

- Filing every speculative concern as a follow-up task or asking the
  coordinator to classify it routinely: the 2026-10-23 correction made such
  cases notes, not work items.

# Relationship to other knowledge

This sets the blocking bar, not the evidence standard: a verdict still says
what was verified and what was taken on trust
([evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md)),
and still states whether a cited harness was shown to fail
([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).
[Review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md)
still governs which sites are checked; this decides which findings block.

# Provenance

Harvested 2026-10-25 from seats `aweb-expert-naapps-verify` (notes
`realistic-review-blockers.md`, `review-evidence-realistic-failure-scope.md`;
naapps relays d8ddb513 and 120f3076, background 714173e9) and
`aweb-expert-pages-data` (note `pages-review-realistic-failures.md`; naapps
41efceb4), with the friction cut relayed in `aweb-expert-pages-requests`
(0376a079) and the mail routing rule in the retired `aweb-expert-secrets-site`
(e0a64d3f). Scope confirmed by the OSS coordinator in f8d89364.
