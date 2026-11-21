---
type: Decision
title: Public refusals include tested recovery
description: Every public refusal a change adds or moves, in the protocol or the aw CLI, ends in a sentence naming the next action a person can take, and a test asserts that text; the supported path and the deciding authority stay unchanged. Operator direction, source-reported.
tags: [decision, aw-cli, protocol, errors, refusals, testing, ux]
timestamp: 2026-11-18
---

**Acceptance:** the operator's general UX rule, relayed to the source by the
coordinator on 2026-11-18. Source-reported; the harvester could not read the
relay, and it is not recorded as the operator's own words.

# Decision

- Every public refusal that a change **adds or moves** ends in a sentence a
  person can act on: the next supported action, such as a command to run or a
  choice to make.
- A test asserts that recovery text. A status or error-code assertion alone
  does not meet the rule.
- The refusal keeps its supported path and its deciding authority. Better
  recovery text must not grant authority, invent a new path, or break a
  working path just to produce a refusal to test.
- The scope is refusals a change adds or moves. It is not an order to rewrite
  every existing message at once.

# Why

A refusal's status or code can stay correct while its human recovery
disappears in a later refactor. A correct denial with no supported next action
leaves the operator stuck. Only a test on the text keeps that recovery part of
the public error contract.

# How it relates

- [Admission init never starts its own login](/aweb-protocol-expert/decisions/admission-init-never-starts-a-login.md)
  and [aw mail reply answers received mail only](/aweb-protocol-expert/decisions/mail-reply-answers-received-mail-only.md)
  are earlier cases. Each refusal names the exact command to run. This
  decision makes that the general rule and adds the text test. It supersedes
  neither.
- [Tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
  still applies. A message test supplements coverage of the component that
  decides the refusal; it does not replace it.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-test-world, 2026-11-18; notes/refusals-include-tested-recovery.md.
