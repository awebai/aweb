---
type: Lesson
title: Attribute denied DNS before changing fixtures
description: Green test targets and a red enclosing egress guard prove different facts; before repairing a fixture, attribute every denied DNS query to the test invocation that issued it with a local diagnostic that answers the denied name itself, then supply the authority through a reserved namespace and the fixture's local registry and rerun the ordinary guard.
tags: [lesson, testing, egress, dns, attribution, fixtures]
timestamp: 2026-11-21
---

The egress guard's DNS sink answers only exact loopback fixture names and
records every other query name (`scripts/test-egress/egress_dns.py` on main
at d8d0bfa1e). It records the name, not the process that asked. So a run can
show every named test target passing while the enclosing stage fails on
denied queries that belong to no visible test.

In one such run every unit target passed and the guard denied four TXT
queries. An instrumented run at the default resolver recorded the call stack
of each lookup and answered the denied name locally. All four came from CLI
subprocesses that minted invites, in two fixture families. Both used
otherwise valid local identities with an empty registry field, so the CLI
went to DNS discovery for the registry.

# How to apply

- **Treat the two verdicts as separate evidence.** A clean leaf exit says the
  assertions held; the guard verdict says what the run reached. Keep the
  failed gate receipt; a green leaf does not overrule it.
- **Attribute every denied query before you change a fixture.** Instrument
  the resolver so each lookup records its caller, and answer the denied name
  locally so the diagnostic never reaches public DNS. The count of attributed
  queries must equal the guard's count.
- **Repair with complete local authority.** Give the fixture a reserved
  namespace (`.test`, not a real domain) and record the fixture's
  already-running registry on the identity, so no lookup happens. Do not
  allowlist the name or loosen the guard. Keep the test's ordinary
  invitation and acceptance assertions.
- **Qualify with the ordinary code and guard.** The diagnostic establishes
  callers and count; only a rerun of the standard guard, with zero denials in
  both the full and the selected receipts, qualifies the fix.

This is the egress case of
[required invariants belong on the fix](/coordinator/required-invariants-belong-on-the-fix.md):
the fix head carries the guard's verdict, not only the targets' assertions.
It also follows
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md):
the fixture names its real local registry instead of relying on discovery.

**Elimination route:** the guard could attribute each denied query to its
caller itself. Until it does, the resolver diagnostic above is the method.

**Status (verified 2026-11-21):** the fixture repair is commit 723556bf6 on a
review branch, not on main at d8d0bfa1e. It moves two `cmd/aw` test families
to `acme.test` and sets the fixture server as the identity's registry URL.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-21; notes/attribute-denied-dns-before-changing-fixtures.md.
