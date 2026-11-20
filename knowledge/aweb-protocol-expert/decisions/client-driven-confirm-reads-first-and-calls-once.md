---
type: Decision
title: A client-driven confirm reads state first and calls once
description: When aw drives an app's confirm from a manifest declaration, with no per-app code, "never confirm twice" is a client rule: read the declared state first, call confirm at most once per invocation, resolve a lost reply by reading state rather than resending, resume a session expiry from the read, and refuse before the call when a one-time output cannot be shown. Retrying confirm and storing the output were rejected. Proposed and under review, not accepted.
tags: [decision, cli, naapp, confirm, one-time-output, retries, secrets]
timestamp: 2026-11-09
---

When `aw` drives an app's confirm from what the app's manifest declares, with
no per-app code in the client, the client cannot rely on the app to make a
second confirm harmless. Some confirms release a one-time output only in their
response: the secrets app's runner registration code is returned in the
confirm response and never stored
(`naapp/secrets/src/aweb_secrets/console_results.py`, module docstring). So
the client owns the rule that a change is never confirmed twice.

# The rule

- **Read the declared state first.** Every start or resume of a confirm reads
  the state the manifest declares before anything else. A change that is
  already done is reported as done and never confirmed again.
- **Call confirm at most once per invocation.**
- **Resolve a lost reply by reading state, never by resending.** If the
  confirm reply is lost, read state again. Done means the change was applied
  and its one-time output is lost and not recovered. Ready means it was not
  applied, and a later run may confirm.
- **Resume a session expiry from the read**, never by repeating the confirm.
- **Refuse before the call when the one-time output cannot be shown**, for
  example when there is no terminal. Producing the output and then losing it
  is worse than not confirming.

# Rejected

- **Retrying confirm on a transport error.** If the server does not guard
  against a repeat, a retry can apply the change a second time.
- **Storing the one-time output for later retrieval.** The secrets app refuses
  this by design: its codes are not persisted.

# Why it is recorded

Any future client-driven flow with a one-time result (runner codes, tokens)
faces the same choice. The obvious moves, a transport retry or a stored
result, are the rejected ones.

# Status

Proposed and under review on 2026-11-09 (task aweb-acwd.4.9, commit
26abe96e3 on branch `agents/aweb-protocol-expert-secrets-docs-session-actions`),
not accepted and not on main. Supersede or remove this concept when review
decides.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/confirm-once-read-first.md.
