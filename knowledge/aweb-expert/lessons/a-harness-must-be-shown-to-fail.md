---
type: Lesson
title: A harness must be shown to fail
description: A red is evidence only if its failure text names the property; a zero is evidence only if the detector was shown positive on the real pattern in a separate invocation; a validated detector is still not a valid experiment until removing the fix makes the harness go red; a fault injector must prove it installed the fault, and a build-breaking mutation is not a surviving one.
tags: [lesson, verification, review, testing]
timestamp: 2026-11-13
---

Recorded by the OSS coordinator role on 2026-07-26 as the durable output of a
security-remediation epic: a handful of real code defects were found, and in the
same period nine failures in the team's own measuring instruments — each of
which would have produced a confident wrong answer, none caught by inspection.

# The rules

- A red is evidence only if its failure text names the property. Environmental
  failures present as timeouts and killed processes and cannot name a property.
  Quote the assertion text, never a pass/fail count.
- A zero is evidence only if the detector was shown positive on the actual
  pattern, repeatably, in a separate invocation; a control in the same
  invocation puts the literal into the searcher's own arguments.
- A validated detector is not a valid experiment. A passing control proves the
  instrument can see; only removing the fix proves the harness can produce the
  condition.
- The control you need depends on the claim's direction: an absence claim needs
  a known positive; a presence claim needs a known negative.
- A partial red is evidence; widening the mutation until everything reds
  destroys the information. Classify every non-red after predicting the
  sensitivity set: expected-sensitive-but-passed is a vacuous guard.
- The harnesses most likely to lack all of this are the ones that are not tests:
  log greps, process counts, exit-code checks, read-backs, roster queries.
- A fault injector must prove it installed the fault before a negative
  assertion about that fault means anything. Before debugging the product, ask
  whether the fault was actually present.
- A mutation that breaks the build can report zero failures, which reads as a
  surviving mutation. Mutate so the code still compiles (for example
  `(cond && false)`), and check for a build failure before reading a count.

# Fault injectors

On 2026-11-13 a live journey's lost-prepare step (run44) was meant to drop the
answer to aw's prepare request at the front proxy. The injector replaced text in
a Caddyfile captured before the signer's site was rendered, never checked that
the replacement matched, and reloaded the result. With no site for the signer
host, the front answered with an empty 200. aw correctly refused that as
`handoff_result_invalid`, the lost-answer path was never exercised, and the
refusal was first read as a client defect.

- A complete 200 is never a lost answer: a handler abort writes nothing (in
  Caddy, the abort panics with `http.ErrAbortHandler`, as the source reports
  from Caddy v2.10.2). An "invalid answer" during a drop-answer test points at
  the injector or the routing, not at the client parser. Do not relax the
  client's refusal to match it.
- An injector captures the current file at enable time, requires exactly one
  match before it mutates anything, and restores exactly afterwards.
- For a wire-level check, `AWEB_HTTP_DIAGNOSTICS=1` reports a per-request
  stage: `await_response` with an error means an abort, and
  `headers_received` means a complete answer arrived.

# Review standard

Any verdict citing a harness carries one of two lines: "the fix was removed and
it redded, at these assertions" or "I did not check whether this harness can
fail." Silence is not acceptable.

# Provenance

The fault-injector rules and the mutation build-failure rule: OKF proposal from
aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/fault-injector-must-assert-it-installed.md and
notes/shell-cp-rm-are-interactive.md. The run44 account and the Caddy source
reading are the source's report; the diagnostic stages were read in
`cli/go/awid/http_diagnostics.go` on main at dfce11678.
