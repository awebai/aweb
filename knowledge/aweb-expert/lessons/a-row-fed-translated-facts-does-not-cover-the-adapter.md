---
type: Lesson
title: A row fed translated facts does not cover the adapter
description: When an authority check is split into a pure rule and an adapter, table rows receive facts that are already parsed, verified or projected, so they prove nothing about the adapter that builds those facts from a real request or row; before deleting a route or DB test in favour of a row, keep one real-input test per translation branch and plant mutations in the adapter alone to show a kept test goes red.
tags: [lesson, testing, mutation, refactoring, authority, table-tests]
timestamp: 2026-11-27
---

A pure rule's table rows hand it facts in their translated form: a verified
internal-auth dict, an `ExistingCohort(matches, live)`. The adapter that turns
a signed request or a stored row into those facts never runs under a row. A
row with the same visible outcome as a real-input test is therefore not its
cover when the row starts from the translated facts.

Seen on 2026-11-27 in E3.4 (install authority). The author deleted
`test_verified_internal_subject_reaches_host_policy[k]` because a row covered
"a forwarded API key". The reviewer changed only the adapter so that it
forwarded a signed `k` principal as `u`. All 28 DB-free rows and the config
tests stayed green, and a signed API-key request then satisfied a users-only
policy. Restoring the deleted test unchanged gave exactly one failure under
that mutation. It is the only test that sends a signed request of each
principal type through the real adapter to the host policy.

# How to apply

Before deleting a route or DB test because a row covers its branch, ask
whether the row receives that test's input already translated. If it does:

- Keep one real-input test per translation branch (for example one per
  principal type, or one per stored-state shape the adapter projects).
- Prove the kept tests guard the translation by planting mutations in the
  adapter alone, leaving the rule untouched: forward one type as another,
  force a projected flag such as `live` or `matches` true, swap two mapped
  fields, read a counter as zero. Each mutation must turn a kept test red.
  Add these to the planted-defect loop alongside the rule mutations.

At E3.6 (federation Phase A) this check was applied before review: four
adapter-only mutations in `commit_phase_a`, run over 446 federation and
contacts tests, were each caught by kept DB tests (forcing `live` true by 1,
forcing `matches` true by 5, swapping the stored hashes by 15, reading the
revision as 0 by 13). No deletion had to be reverted.

This is the translation case of
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md):
the real verifier and the real rows stay under test even when a pure rule
decides the verdict. The mutations follow
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
a mutation placed in the rule says nothing about the adapter.

# Limits

As of 2026-11-27 this was seen at two Python sites (E3.4 install authority and
E3.6 federation Phase A), on the source's branches and not yet on main. The
review return, the ACK and the E3.6 mutation counts are source-reported.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/a-pure-rule-must-keep-the-read-order.md. Checked by the harvester:
commit 94048077bb on `agents/aweb-expert-contracts-adze4` restores
`test_verified_internal_subject_reaches_host_policy[u]` and `[k]` unchanged,
and its message says forwarding a signed API key as a user passes every table
row and fails the `[k]` case; `ExistingCohort` and `commit_phase_a` are in
`server/src/aweb/federation/authority_state.py` on
`agents/aweb-expert-contracts-adze6`.
