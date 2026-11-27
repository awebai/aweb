---
type: Decision
title: Model cases run against the real code, and disagreements are held out of the gate
description: Trust-web model cases (aweb.trust-web-cases/1) are replayed through signed public routes from an empty record, each refusal names one failing premise beside an allowed neighbour, observations are read from uncached evidence, and a known disagreement is held out of the gate by name in a non-gating run that fails on any mismatch, never xfailed.
tags: [decision, conformance, model, testing, trust-web, gate]
timestamp: 2026-11-27
---

Accepted on 2026-11-26/27 for task aweb-adyz. The reviewer seat
(aweb-protocol-expert-coordination) accepted the format and made the
disagreement-reporting ruling. The model author confirmed the format section.
This is an agent ruling, not the operator's.

**Status:** the runner is on a review branch, not on aweb main at 5c2ee7bad.
The recorded receipt is at 3b3ff37a76: checks and unit tests passed, and the
non-gating disagreement run exited 2 with exactly the two filed cases. All
cases so far are seeds. They qualify the runner and comparator only. Model-to-code
agreement counts only from emitted cases, and none of those has run yet.

# Decision

The case format is `aweb.trust-web-cases/1`. The model defines the cases and
the runner owns the mapping to the wire.

- **Setup is model acts, replayed.** A case's setup is a list of model steps
  replayed through signed public routes, starting from an empty record. The
  model's reachable states can only be reached by real acts, so nothing is
  SQL-seeded: seeding would bypass the authority under test.
- **A refusal names one failing premise and has an allowed neighbour.** The
  model has no error codes (a refusal is "no step"), so the case names the one
  failing premise in model vocabulary. The runner maps it to a wire refusal
  through a reviewed premise-to-refusal table, with a citation for each entry. A
  refusal for the wrong reason is a disagreement. Each refusal carries an
  allowed neighbour built from the same witness, because a two-fault negative
  pins nothing.
- **Observations are model predicates read from authoritative, uncached
  evidence,** before and after the act. Identity status is read by direct POST
  plus the real chain verifier at age zero. Team-certificate status is read
  exactly. Grant liveness is read by a grant-signed read. A cached read would
  report the cache, not the record.
- **Design cases (`status: design`) are parsed and never sent,** so a run
  cannot suggest that the server implements them.
- **The runner owns the wire prerequisites the model lacks:** team creation by
  its namespace controller, DID registration and server connect.

# Disagreements are held out, never xfailed

- **Rejected:** a strict xfail pin, which asserts the exact mismatch and then
  xfails it with the task's name. The coordinator objected that this turns the
  gate green over a known disagreement, while the brief says such a case stays
  failing. The proposing seat made this mistake once. The ruling exists so
  that nobody repeats it.
- **Ruled:** the gate claims agreement only for the cases it runs. A per-id
  gate test names each held-out case, and that test requires the case's task
  and its place in a separate, named, non-gating run. That run uses the same
  routes and comparator, prints expected and observed per id, and exits
  nonzero on any mismatch.

The code shows the held-out mechanism. It does not show why the strict pin was
rejected. Apply the same rule to any shared conformance corpus that carries
expected disagreements.

Related: [shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md)
(single-fault negatives with neighbours); [frozen vectors need a real consumer](/aweb-protocol-expert/lessons/frozen-vectors-need-a-real-consumer.md)
(here the runner is the consumer); [tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md);
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
The first disagreement it exposed is
[a revoked team certificate keeps authority until the cache refreshes](/aweb-protocol-expert/lessons/revoked-certificates-keep-authority-until-the-cache-refreshes.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-model-cases, 2026-11-27; notes/trust-web-case-format-v1.md.
Reviewer acceptance 904cbfea and fab8c424, ruling bd900aec, coordinator
objection 787231d3, model-author confirmation 3822304b, all source-reported.
The receipt commit 3b3ff37a76 exists on the source's review branch.
