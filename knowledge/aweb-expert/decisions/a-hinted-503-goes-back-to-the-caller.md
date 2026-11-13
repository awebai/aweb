---
type: Decision
title: A hinted 503 goes back to the caller, which waits it only within each step's own bound
description: The server sends a delta-seconds Retry-After only for typed registry throttling; aw's transport returns a hinted 503 at once instead of blind-retrying it; a protected command step waits a hint only if it fits that step's own bound and the caller's deadline, and the installation lookup and the prepare each get a fresh bound.
tags: [decision, aw, protected-operations, retries, throttling, deadlines, registry]
timestamp: 2026-11-13
---

The contract was agreed on 2026-11-13 by the aweb-expert seat working on owner
acts, the server seat and the security sweep, after run46 failed.

# What went wrong in run46

The registry throttled the server's fresh key read during request
authentication. The server dropped the throttle's 53 s hint and answered a
bare 503. aw's transport (`awid.Client`) then retried it three times in
0.7 s, repeating the throttled read each time. That gave four 503s at gaps of
about 110, 220 and 410 ms. The protected revoke's installation lookup gave up,
and aw exited before preparing.

# Decision

- **Server:** only a typed `RegistryThrottled` carries a retry delay through
  the identity observation. The HTTP adapter then answers
  `503 identity_binding_unavailable` with a delta-seconds `Retry-After`.
  Fractions round up, the minimum is 1 s, and an invalid delay sends no
  header. The server never waits or retries itself, and caches no failure.
  An identity mismatch stays a 403, and other dependency failures send no hint.
- **Client transport:** a 503 that carries `Retry-After` returns to the caller
  at once, with the hint. A bare 503 keeps the transport's brief bounded
  retries.
- **Protected command:** a step waits a delta-seconds hint only if the wait
  fits that step's own bound (`handoff.DefaultRetryWithin`, 2 minutes) and the
  caller's deadline. Then it reads again. A hint that does not fit, an
  HTTP-date hint or no hint ends the step as unavailable. A 404, an inactive
  installation or a manifest mismatch refuses at once.
- **Each step has its own bound.** The installation lookup and the prepare
  each get a fresh bound, so a command can spend up to about 4 minutes waiting
  out hints before it signs. Never describe this as one 2-minute command
  budget. A local act reads once, within the API timeout.

# Rejected

- **Waiting on every 503.** That turns a fail-closed refusal into an
  indefinite wait.
- **Fixing one side only.** A server hint is useless while the transport
  blind-retries, and the client's 30 s API deadline cannot hold a 53 s wait.
  The client cannot honour a hint the server never sends.
- **Changing the journey's limiter fixture** so that the lookup avoids the
  throttle. That hides the failure instead of fixing it.

# Status

Verified by the harvester on 2026-11-13: the client half is b7409d911, on the
branch `agents/aweb-expert-owner-acts-throttle-hint`. The server half is
5de49203e, on `agents/aweb-protocol-expert-security-sweep`. Neither is on main
at f5fa94683. The source reports that both were ACKed in review and composed
as 1b1fc7eea. The journey has not yet been rerun under the real limiter.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/throttle-hints-are-the-callers-to-wait.md. The harvester read the
commit messages of b7409d911 and the server diff of 5de49203e. The run46
diagnosis and the review verdicts are the source's report.
