---
type: Decision
title: Tests assert behaviour, not product wording
description: The operator's rule, applied in the naapp lanes - a test asserts a status, a code or an effect, never the prose of a refusal or message; a refusal that carries only prose is a product finding (give it a code), and until the code exists the test stays status-only.
tags: [decision, testing, refusals, naapps]
timestamp: 2026-11-24
---

The operator's rule, applied by the naapps coordinator in its ruling 2d12bea6
on a Folio test audit (2026-11-25 by the source's clock). The acceptance is
**source-reported**: the harvester could not read the ruling.

# The decision

- A test asserts behaviour: an HTTP status, a structured error code, a state
  change or another observable effect. It never asserts the wording of a
  refusal, an error detail or a user-facing message.
- Matching a phrase by regular expression was rejected. It still pins
  wording.
- When a refusal carries only prose, so a test has nothing but the status to
  assert, that is a **product finding**: give the refusal a code. Keep the
  status-only check until the code exists, then assert the code.

# Why

An assertion on prose pins wording that the product owns and should be free
to change. It turns a copy edit into a red test, and the test still does not
show that the behaviour is right. In the audit, e2e checks were strengthened
with refusal details such as "Team certificate has been revoked". The ruling
withdrew them.

The prose was also a product gap. naapp-lib's `runtime/team_auth.py` already
has the coded pattern (`detail={"code": ...}`), but many of its refusals carry
prose only. At least one branch compares prose: it checks
`exc.detail == "Unknown AWID team"` to decide caching. That is code depending
on wording, the same coupling this rule keeps out of tests.

# Limits

The rule is about tests of our own product's wording. Prose that a released
client parses is a compatibility surface. A test that pins it guards that
consumer, and this rule does not remove it. See
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-24; notes/2026-11-25-tests-assert-behaviour-not-prose.md. Checked by
the harvester at naapp main: the `"Unknown AWID team"` comparison and the
coded-detail helper in `naapp-lib/src/aweb_naapp/runtime/team_auth.py`.
