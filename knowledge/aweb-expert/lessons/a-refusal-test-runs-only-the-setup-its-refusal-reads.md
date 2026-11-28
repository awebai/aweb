---
type: Lesson
title: A refusal test runs only the setup its refusal reads
description: A negative test that seeds registry or database state the verifier never consults before refusing gains nothing and inherits that setup's timeouts, so a database stall fails it with no refusal; present the refusal without the unused setup, assert the vector's own expected error, and reproduce such a stall with a real Postgres lock from a second connection.
tags: [lesson, testing, flaky-tests, awid, naapp, postgres]
timestamp: 2026-11-27
---

The naapp-lib team-auth negative vectors registered a team and a certificate
through AWID's real routes before presenting each flawed request. The verifier
refuses all four negative vectors (path, audience, body, version) at the
signed-payload check, before its first AWID read, so that setup never
influenced the result.

It still had a cost. AWID runs in the test's own event loop through
`ServiceTransport`, so the registry client's production 5 s per-request budget
also bounds AWID's server-side database work. Under gate load a database stall
in the seeding failed the test with "AWID registry unavailable (TimeoutError)",
and no refusal came back at all. The test asserted only a 401, so the seeding
did not even pin why the request was refused.

# How to apply

- When a refusal test is flaky, first check whether it runs setup (registry
  writes, database seeding) that the refusal path never reads. Remove that
  setup from the negative cases: they then depend only on the check they test.
  The verifier under test is still the real one, as
  [tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
  requires; what goes is setup that no authority consults.
- Assert the vector's own expected error, not only the status code. Once the
  setup is gone, the error is what proves the request was refused for the
  vector's reason and not for a missing team.
- Reproduce a database stall with a real lock: hold an `ACCESS EXCLUSIVE` lock
  on a table the setup writes, from a second connection, across the setup.
  That is no mock and needs no timeout change. Here it gave the gate's exact
  message after 5.6 s. With the lock still held, the unseeded negatives all
  returned 401 with their expected errors in about 1 s. Raising the timeout
  instead would hide the dependency, not remove it.

This confirms [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md):
injected latency reproduced what load alone could not.

# Limits

What stalled the gate's database for 5 s is not established. The hypothesis is
CPU oversubscription in the unit stage, with several suites and their Postgres
sharing an unlimited runner. Positive vectors, and every other test that seeds
through this harness, stay exposed to the same 5 s budget. The counts (4 of 4
negatives red under the lock before the fix, 8 of 8 green after) are
source-reported; the harvester did not rerun them.

Evidence: OKF proposal from aweb-expert/aweb-expert-release-flakes, 2026-11-27; notes/refusal-vector-tests-seed-awid-they-never-read.md. Gate run vm-c233588b for server-v1.27.56; fix 5455993ca5, red at 138bdd540a.
