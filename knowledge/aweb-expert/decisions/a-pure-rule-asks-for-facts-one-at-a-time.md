---
type: Decision
title: A pure rule asks for its facts one at a time
description: When an authorization rule's lookups can refuse or fail on their own, the pure "facts in, verdict out" function returns NeedFact for each lookup in the rule's own order and the caller loops, reading exactly that fact; reading every fact first is rejected because it changes which refusal a multi-fault request gets and makes reads the old code never made; the table driver asserts the sequence of reads, not only the verdict.
tags: [decision, refactoring, authority, error-precedence, testing, python]
timestamp: 2026-11-27
---

Epic E3 turns each authorization rule into one pure function: the caller reads
the facts, the function returns a verdict with its refusal code, and the site
promises no behaviour change. In aweb's messaging rules the lookups are not
passive. A selector lookup can itself refuse (an unknown `~team`, an ambiguous
identity, a registry error), a shared-team membership read can raise a
retryable registry error, and a kind query runs once per recipient.

# Decision

- **The rule asks; the caller reads.** The function returns either a verdict
  or `NeedFact(<which fact>)`, in the order the old code needed the facts.
  Unread facts carry an `UNREAD` sentinel. The caller loops while the result
  is a `NeedFact`, reads exactly that fact with the call the old code made,
  then maps the verdict to the old exception.
- **A failure the old code caught and deferred becomes a fact value.** At the
  delivery-policy site a failed membership read is recorded as `UNAVAILABLE`,
  and the verdict tells the caller to raise the exception it is holding. The
  precedence of that error is then part of the pure rule, not of the caller.
- **The table driver asserts the reads.** It feeds answers to each `NeedFact`
  and records what was asked; a row asserts the sequence of lookups as well as
  the verdict, and a lookup the row did not expect fails the test. Laziness is
  then under test, not assumed.

# Rejected

- **Read every fact up front, then decide.** A request with two faults is then
  refused for a different one than before, which changes released behaviour.
  Network and database reads also happen that the old code never made: an open
  recipient would read memberships and contacts, and a contacts-only recipient
  would read memberships. Existing tests asserting "no registry call" break,
  correctly.
- **Pass async lookup callbacks into the rule.** The function is then no longer
  pure, and the table needs fakes.

# Counting the tests a rule replaces

A test that passes through a rule is not a test of the rule. Classify each
candidate DB test by what its assertions prove before counting it as replaced
or as needing a row. At the delivery-policy site the plan counted the 99
same-origin delivery tests, which prove routing and residence; only five of
the deleted tests asserted nothing but a verdict.

# Limits

As of 2026-11-27 this shape was used at three sites in aweb's Python messaging
package (mail target E3.2, delivery policy E3.1, human-kind chat E3.3), each
reported ACKed by the protocol expert's coordination seat with no behaviour
change, on the source's branches and not yet on main. It has not been tried on
the Go sites (E3.7) or on the remaining server and registry sites. Sites whose
conditional reads cannot refuse on their own may not need the loop; the
invariant that does not change is that a refactor keeps the old read order and
skips the reads the old code skipped.

# Relationship to other knowledge

[Tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
makes the pure function the authority for its rule; this decision is how to
get there at a site whose reads can refuse. A table row that replaces a
deleted DB test must also carry that test's facts:
[a table row carries the deleted test's facts](/aweb-expert/lessons/a-table-row-carries-the-deleted-tests-facts.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/pure-rule-asks-for-facts-lazily.md. Checked by the harvester: commits
e17b2c8bd (E3.2: `NeedFact`, `UNREAD`, a driver that records the lookups
asked), 1b2029082 (E3.1: `SharedTeam.UNAVAILABLE`) and e2b275e9b (E3.3) on the
source's `agents/aweb-expert-cleanup-oss-e3-*` branches. The ACKs and the test
counts are source-reported.
