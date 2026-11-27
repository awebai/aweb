---
type: Decision
title: Per-item facts make a pure rule a generator
description: When a pure "facts in, verdict out" rule needs one lazily read fact per item of an unbounded list, it is a generator that walks the list once, yields each needed fact, is sent the answer and returns the verdict; restarting the rule from scratch after each fact is rejected because it is quadratic, and the rule's table carries a traversal-count control shown red on the restarting version.
tags: [decision, refactoring, authority, performance, testing, python]
timestamp: 2026-11-27
---

Epic E3 turns aweb's authorization rules into pure functions. Where a rule's
lookups can refuse or fail on their own, the rule asks for one fact at a time
in the old code's order, and the caller reads exactly that fact and calls the
rule again. Restarting the rule after each fact is fine when the facts are a
fixed handful (three at the delivery-policy site E3.1, four at the mail-target
site E3.2).

# Decision

- **One fact per item: the rule is a generator.** It walks the items once,
  yields a request for each fact it needs, is sent the answer, and returns the
  verdict. The caller drives it with `send`. The reads, their order, the
  labels and the refusal stay as they were.
- **The table carries a traversal-count control.** Rows count how often the
  rule reads each item, across a list long enough to show the difference, and
  require exactly one read per item. The control is shown red on the
  restarting version before the generator is accepted.

# Rejected

- **Restart from the first item after each fact.** With one fact per item
  the rule rescans the list after every answer: N items cost N(N+1)/2 row
  visits for N reads. The human-kind chat rule (E3.3) has one kind read per
  recipient and no recipient cap. Every table test passed on the restarting
  version, because they check verdicts and read sequences, not how often a
  row is visited.

# How to apply

For any E3-style extraction over a list (recipients, members, contacts),
count the facts per call. If the count grows with the input, write the rule
as a generator from the start and add the traversal-count row.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/pure-rule-asks-for-facts-lazily.md. The restart cost was found in the
E3.3 review by the protocol expert's coordination seat, which reported a
512-recipient probe and ACKed the fix (source-reported). Checked by the
harvester: commit 11527a650b on the source's E3 chat branch, not yet on main,
which makes `decide_agent_chat` a generator and adds
`test_each_recipient_is_decided_once`; its message reports the test fails on
the restarting commit e2b275e9b0, with the first row read 66 times across 65
recipients.

This refines the ask-one-fact-at-a-time shape for E3 rules, which was
harvested separately from the same source and was pending review when this
was written.
