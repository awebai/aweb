---
type: Decision
title: A pure verdict keeps the caller's lazy fact reads
description: When a rule tangled with I/O is split into a pure verdict and some of its reads are conditional, the caller keeps reading lazily in the order the verdict consumes the facts and stops when an earlier fact decides; the gating condition is a predicate on the facts type shared by reader and verdict; reading every fact first is rejected because it changes which errors appear.
tags: [decision, refactoring, authority, error-precedence, go]
timestamp: 2026-11-26
---

Epic E3 splits rules that are tangled with I/O into pure verdicts: facts in,
verdict or refusal out. Each site is promised "no behaviour change". This
decision covers sites where some reads are conditional, meaning a read that
can fail is skipped once an earlier fact has decided.

# Decision

- **The caller keeps reading lazily.** It reads facts in the order the verdict
  consumes them, and it stops as soon as an earlier fact decides.
- **The gating condition has one owner.** The condition that decides whether a
  read happens is a predicate on the facts type. Both the reader and the
  verdict use it, and it gets its own small table test. The caller does not
  keep a second copy of the rule to decide what to read.
- **Reads that only serve the chosen outcome come after the verdict.** For
  example, workspace selection reads the certificate and signing-key paths
  only for the membership it selected.

# Rejected

- **Read every fact, then decide.** This looks purer, but a read that can fail
  (a broken team certificate, an identity-home preflight, a directory scan)
  then fails on paths that never ran it, and error precedence moves. That is a
  behaviour change on a refactor that promised none. It shows up only as a
  different error on a broken home, and tests rarely cover that, so a green
  suite does not catch it.
- **A two-phase verdict that asks for more facts.** It adds more machinery
  than the rules it serves.
- **Calling the verdict twice.** Rejected for the same reason.

# How to apply

When doing or reviewing an E3 site, list every read the verdict consumes and
mark the ones that can fail. For each read that is skipped on some path, check
that it is still skipped there after the change, and that the condition gating
it is the shared predicate, not one rebuilt inside the caller. A test that
points a broken home at a path that never read it is the way to prove a site
did not move an error.

# Status

As of 2026-11-26 the decision was applied at one site family in the Go CLI
(creation authority, team-extend creator discovery, workspace selection) on
the source's branch, with review requested from the protocol expert. It was
not yet on main or reviewed. E3 has seven such sites across the server, the
registry and aw.

# Relationship to other knowledge

[Tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
makes the pure function the authority for its rule. This decision covers how
to get there without changing behaviour.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-aw-contract, 2026-11-26;
notes/pure-verdict-lazy-fact-reads.md. Task aweb-adze.7 (E3.7). The source
branch at 72d33c272e defines `takesAPIPath` and `needsCertificate` on
`creationAuthorityInput`, used by both `readLocalCreationFacts` and
`decideCreationAuthority` in `cli/go/cmd/aw/creation_authority.go`.
