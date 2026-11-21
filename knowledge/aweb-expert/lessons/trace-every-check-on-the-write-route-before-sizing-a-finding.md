---
type: Lesson
title: Trace every check on the write route before sizing a finding
description: Before sizing or exploiting a registry-trust finding, trace every check on the write route, not only the named validator; AWID's team-server publish runs a second origin check, so the production-reachable form was an https name resolving to an internal address, not loopback.
tags: [lesson, review, security, ssrf, awid, testing]
timestamp: 2026-11-18
---

A finding about what a registry will store was sized from the record validator
alone. AWID's team-server publish route also calls `validate_delivery_origin`
after that validator, and outside development it refuses localhost and literal
IP addresses. The loopback form of the finding was therefore unreachable
against a production registry. The production-reachable form was an https name
that resolves to an internal address, which the registry accepts whatever it
resolves to.

- **Trace the whole write path.** Before sizing a registry-trust finding or
  writing its exploit test, follow every check the write route runs, not only
  the validator the finding names. Sizing from one validator mis-targets tests
  and misleads routing.
- **The client rule still stands.** The second check narrows the finding; it
  does not remove it. A client must not rely on its registry's policy, which is
  why team-server reads go through egress
  ([tenant-chosen URLs go through egress](/aweb-expert/decisions/tenant-chosen-urls-go-through-egress-with-an-exact-origin-allowlist.md)).
- **Run the registry like the e2e stacks.** A real-path test that publishes a
  loopback team server gets 422 until AWID runs as the e2e stacks run it:
  development environment plus insecure delivery origins allowed
  (`APP_ENV=development`, `AWID_ALLOW_INSECURE_DELIVERY_ORIGIN=1`).

Observed on `main` at 1277041b2b (`awid/src/awid_service/routes/teams.py`,
publish route; `awid/src/awid_service/delivery_origin.py`).

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-egress, 2026-11-18; notes/awid-publish-second-origin-check.md.
