---
type: Lesson
title: Review the operator's worst-case sentence like a contract
description: A custody or risk question goes to the operator only after the reviewer has ACKed the exact worst-case sentence the operator will read; every "cannot" in it follows from a rule the system enforces, unenforceable custody practices are stated as requirements on the holder, and a question already sent with a bound later shown wrong is explicitly held or retracted.
tags: [operator, review, custody, risk]
timestamp: 2026-11-28
---

The operator decides a custody or risk question on its worst-case sentence
alone, and nobody downstream re-checks that sentence. An overstated bound is a
wrong decision input that looks like a settled one.

In one case, a pilot-held grant-key custody decision went to the operator with
the design's own worst-case summary. Protocol review then disproved that
summary three times in a row:

- a leaked key's reach was not limited to bindings the controller had bound,
  because verification also accepted the actual-parent issuer;
- "cannot affect a person after rotation" contradicted a fresh designation the
  design itself permitted;
- "no effect in other namespaces" rested on non-reuse, which the registry
  enforces only per namespace.

The reviewer NACKed four times, and the last NACK was on the custody wording
alone. The text finally ACKed was the reviewer's own wording plus one sentence
making key dedication a requirement on the holder. The coordinator had already
sent the earlier summary onward. It had to ask for that message to be held, and
then send the exact reviewed text.

## How to apply

- Hold a risk or custody question until the reviewer has ACKed the exact
  sentence the operator will read. Do not forward the author's summary and
  correct it later.
- For each "cannot", ask which enforced rule makes it true. If no rule does,
  restate the claim as a requirement on the holder, or drop it.
- When the reviewer supplies wording, the author adopts it verbatim. The
  coordinator checks the diff itself before routing it.
- If a question has already gone out and review shows its bound is wrong,
  explicitly hold or retract that message, then send the reviewed text.

This refines [ask the operator self-contained questions](ask-the-operator-self-contained-questions.md):
a self-contained question also needs a reviewed worst case. It rests on one
case so far.

Evidence: OKF proposal from coordinator/approval-service, 2026-11-28;
notes/operator-worst-case-wording-is-reviewed-like-a-contract.md. The review
went through awebai/aweb commits 54e6f37, becfc53, 67c8027 and 0fa69da.
