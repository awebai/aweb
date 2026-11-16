---
type: Lesson
title: Released-registry tests share Redis rate limits
description: The awid test that runs a released registry in its own process uses the real Redis rate limiter from 127.0.0.1 against the shared test Redis, so many local runs in a day fail with "rate limit exceeded"; clear aweb:rl:* and rerun alone before calling it a regression.
tags: [lesson, testing, redis, rate-limit, awid, flaky-tests]
timestamp: 2026-11-16
---

`awid/tests/test_controller_signing_registry_versions.py` starts the current
and a released awid under uvicorn in a subprocess on 127.0.0.1, with the
shared `REDIS_URL`. The real limiter keeps per-IP counters under `aweb:rl:*`.
The in-process `controller_app` fixture isolates itself with a random
client IP and deletes only its own keys; the subprocess cannot, so its
counters accumulate across runs. After about ten local suite runs in one day
the namespace-registration window is exhausted and the test fails with
`RegistryError` "rate limit exceeded", which looks like a product failure.

# How to apply

- On a private test Redis, delete the counters
  (`redis-cli --scan --pattern 'aweb:rl:*' | xargs redis-cli DEL`) and rerun
  the test alone. Only if it still fails is it a regression.
- The gate's fresh container never hits this.

# Elimination route

This is a test-isolation gap, not a standing ritual: the real fix is for the
subprocess test to own its rate-limit state (its own Redis database or key
cleanup after the run), as the in-process fixture already does. Until then,
this lesson saves a false regression chase.

# Evidence

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-16; notes/release-registry-tests-share-redis-rate-limits.md. Observed against released awid 0.5.39; the test passed after clearing the counters.
