---
type: Decision
title: A non-waiting protected operation sends no callback and reads its receipt once
description: A protected command that does not wait for the human (aw id endorse --no-wait) prepares, verifies and presents the page exactly as the waiting path does, but sends no loopback redirect_uri and reads the receipt once; an unreadable receipt is unresolved, never a settlement, and a rerun with the same operation id finishes the operation.
tags: [decision, aw-cli, protected-operations, handoff, oats]
timestamp: 2026-11-13
---

Decided on 2026-11-13 by the aweb-expert seat that built `aw id endorse
--no-wait` for OATS, ACKed in review. OATS needed setup that an agent drives
not to block for as long as the operation's lifetime. The decision is on main
in ac2d18495 (`GovernanceOptions.NoWait` in the handoff client).

# Decision

- **Same preparation as the waiting path.** The command prepares the
  operation, verifies it, runs the policy check and presents the page exactly
  as a waiting run does. The caller receives the verified page, digest,
  fingerprint and expiry.
- **No redirect_uri.** No loopback listener survives the command, so a
  callback would send the human's browser to a dead port. A later rerun reads
  the receipt instead.
- **One receipt read.** A pending receipt is reported (operation id, state,
  page, digest, fingerprint, expiry) and the command exits 0. A committed
  receipt continues to certificate verification, registration and read-back
  with no human wait. A read failure is an unresolved receipt
  (`receipt_unavailable`), never a settlement.
- **Resume by operation id.** A rerun with the same `--operation-id` resends
  the saved prepared bytes, as the waiting path's resume does. Callers that
  wait (the default) are unchanged.
- **`--no-browser` is a separate flag.** An agent driving setup wants both
  flags. A human at a terminal may want to wait without a browser being
  opened for them.

# Rejected

- **A server-side "detached" mode.**
- **A local listener that outlives the command.**

Both add state that the client cannot reconcile after a crash. The receipt is
already the durable answer.

# How to apply

A future protected command that returns before the human acts follows the same
shape. It sends no callback it cannot receive, treats the receipt as the only
answer, and never reads a failed read as approval or refusal.

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/no-wait-endorse-sends-no-callback.md. Commit ac2d18495 is on main, and
its message and the handoff client match the decision. The review ACK
(8b24c880) is the source's report.
