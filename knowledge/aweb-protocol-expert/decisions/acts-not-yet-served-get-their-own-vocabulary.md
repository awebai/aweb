---
type: Decision
title: Acts not yet served get their own vocabulary
description: A new owner act gets its own vocabulary constant (HUMAN_ROLE_ACTS / HumanRoleOwnerActs) until an app serves it, because deployed apps pass APP_ACTS to their verifier as its closed list and widening it is a behaviour change for every importer; widening APP_ACTS was rejected. Ruled by the coordinator; on a review branch, not on main.
tags: [decision, owner-act, vocabulary, compatibility, naapp]
timestamp: 2026-11-09
---

The human-role owner acts live in their own constant, `HUMAN_ROLE_ACTS` in
Python and `HumanRoleOwnerActs` in Go. They do not join `APP_ACTS`. Each app
adopts them when it moves to the delivery route that serves them.

# Why

A verifier's vocabulary constant is deployment policy, not a list of names.
On aweb main (161f02d1f) the secrets app (`composition.py`) and the logs app
(`reader_service.py`) pass `APP_ACTS` straight to their owner-act verifier as
its closed list. Adding the human-role acts to `APP_ACTS` would make those
live contact-act routes verify an act they have no handler for. The outcome
would then depend on each route's subject handling instead of the
closed-vocabulary refusal (`act_not_allowed`).

# Rejected

Widening `APP_ACTS`. The contract calls the acts additive, but adding them to
the deployed vocabulary changes behaviour for every caller that imports it.
This is the same rule as
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
and [removing an implicit side effect is a contract change](/aweb-protocol-expert/lessons/removing-an-implicit-side-effect-is-a-contract-change.md):
an addition is additive only if no deployed importer's behaviour changes.

# How to apply

Before adding a value to a shared constant, find every importer. If any
importer uses it as an allowlist, the addition is a behaviour change. Give
the new values their own constant until each importer opts in.

# Status

Ruled by the coordinator on 2026-11-09 in task aweb-acwd.4.1. Implemented at
b26a90e7f on a review branch, not on main. On main, `APP_ACTS` holds only the
app-role and app-credential acts.

Related: [a signed vector needs its signer first](/aweb-protocol-expert/lessons/a-signed-vector-needs-its-signer-first.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/separate-vocabulary-for-acts-not-yet-served.md.
