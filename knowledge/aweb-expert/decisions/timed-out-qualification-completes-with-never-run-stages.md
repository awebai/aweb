---
type: Decision
title: A timed-out qualification completes with its never-run stages
description: When a controller timeout stops a full gate after some stages passed, one follow-up session at the same SHA runs only the stages that never ran, and the two sessions' logs together are one pass; the gate ledger records nothing on a timeout, and rerunning passed stages tests the same code state twice.
tags: [decision, testing, gates, qualification]
timestamp: 2026-11-11
---

Agreed with the coordinator on 2026-11-11, during the VM qualification of
acwx 579b220bd.

# Decision

- A qualification stopped by a timeout is completed by **one** follow-up
  session at the **same SHA**.
- The follow-up runs only the stages that never ran, with an explicit stage
  set (`AWEB_CANDIDATE_STAGES`), the same frozen origin and a larger timeout.
- The evidence for the stages that passed is their logs at that exact SHA.
  The two sessions' logs together are one pass.

# Why

- The gate writes its ledger only when its child exits normally. On SIGINT or
  SIGTERM it exits without recording anything (`scripts/candidate-docker-gate.sh`
  on main at 7f4be32fa). The default entry point would then rerun every stage.
- Rerunning stages that already passed at an unchanged SHA tests the same code
  state twice, against the operator's direction.

# Rejected

- **Rerunning the whole gate after a timeout.** It spends the full gate time
  again to re-prove stages that already passed on the same bytes.

The same principle covers failures: never rerun an unchanged SHA after a
deterministic failure; see
[the first run on a new host type is a portability test](/aweb-expert/lessons/first-run-on-a-new-host-is-a-portability-test.md).
A split pass is still bound to one SHA:
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-11; notes/split-run-completes-one-pass.md. The coordinator's agreement
is source-reported. The ledger behaviour was read on main at 7f4be32fa.
