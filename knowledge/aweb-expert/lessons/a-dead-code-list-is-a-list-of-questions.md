---
type: Lesson
title: A dead-code list is a list of questions
description: Tool-reported dead code ("unreachable from a binary", "named by no Makefile target, gate or workflow") is not unused; check each item for consumers the tools do not see, delete outright only what has no consumer of any kind, and route the rest to its owner with the consumer named, together with the registry edits a deletion would need.
tags: [lesson, cleanup, review, conformance, judgment]
timestamp: 2026-11-12
---

On 2026-11-12 a stale-cleanup task worked from a deployment review's "no-risk"
removal list. The list came from deadcode and vulture, plus a check that
nothing in a Makefile target, gate or workflow named the item. Checked one at a
time against aweb main (f591d34e8), many items still had a consumer that the
tools did not see:

- two Go signers whose tests were the registered Go consumers of two public
  vectors (in the vector provenance gate, the vectors README and the identity
  coverage inventory);
- a canonical-JSON Go file used by other Go files;
- a compose file that is a fixture in a gate test run from the Makefile;
- three documented opt-in scripts;
- a spike with a server test and provenance and inventory entries;
- a naapp-lib egress method that httpcore calls by name through its network
  backend interface (it is the guard that refuses Unix sockets);
- a vendored vector snapshot whose only test had been deleted, but which the
  provenance gate's self-test still byte-checked;
- an "unused" import that a test reached through a multi-line import. A
  single-line grep missed it and a syntax-tree import search found it.

Only the items with no consumer of any kind were deleted. The rest went to the
coordinator, each with its consumer named. The coordinator deleted some of them:
the Go signers, which nothing shipped (so Go dropped out of those vectors'
conformance evidence), the spike with its test and gate entries, and the
snapshot with its gate check. It kept the others: the canonical-JSON file, the
documented scripts and the gate fixture. So routing was the right call, and
"route" does not mean "keep".

# How to apply

- Read "unreachable" or "not named by any target" as a question about who
  consumes the item. Before deleting, look for consumers the tools miss:
  - a test registered as a conformance consumer of a public vector;
  - a fixture used by a gate test;
  - a documented opt-in tool or script;
  - a method that a library calls by name through an interface;
  - a vendored snapshot that a gate still checks;
  - a re-export reached through a multi-line import. Search imports with a
    syntax tree, not a line grep.
- Delete outright only what has no consumer of any kind. Send each other item
  to its owner with the consumer named. The owner decides, and may still
  delete it.
- A deletion the owner approves includes its registry edits in the same
  change: the vector provenance consumer list, the vectors README, the identity
  coverage inventory and the results docs. These edits only come to light once
  the consumer is named.
- The real fix is for dead-code review to read these registries itself. Until
  it does, the check is manual.

This refines
[verify business facts; consolidate before cutting](/aweb-expert/lessons/verify-business-facts-and-consolidate-before-cutting.md)
for dead code reported by tools. A deletion is also a contract change, so the
consumer search of
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
applies to it too.

Evidence: OKF proposal from aweb-expert/aweb-expert-stale-cleanup, 2026-11-12;
notes/dead-code-means-no-consumer-of-any-kind.md. One repository, one review.
