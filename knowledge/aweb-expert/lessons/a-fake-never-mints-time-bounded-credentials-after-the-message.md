---
type: Lesson
title: A fake never mints a time-bounded credential after the message time is fixed
description: A test fake that builds a time-bounded artifact, such as an encryption-key assertion, inside a callback that runs after the code under test fixed its own second-truncated timestamp fails whenever a second boundary falls between the two clocks; it looks like order dependence in a loaded gate. Build what custody holds before the call, or pass the payload's time as now, and prove the diagnosis by forcing the crossing.
tags: [lesson, testing, timing, flaky-tests, fakes, e2ee]
timestamp: 2026-11-27
---

# The discovery

A release gate failed one MCP chat test with
`messaging_tool_internal_error failure_type=ValueError`. The test passed
alone and in the previous gate on the same base. The first diagnosis was
"order-dependent or shared state". That was wrong.

`chat_send` fixes the message time, truncated to the second. The envelope
then validates the sender's encryption-key assertion at that time, and
awid's `validate_encryption_key_assertion` refuses a `created_at` in the
future. The test's hosted-encryptor fake built the custodial assertions
inside the encryptor callback, which runs after the message time is fixed.
The assertion's time is also truncated to the second. So whenever a second
boundary fell between the two reads, the assertion was newer than the
message it sealed. A loaded gate makes that window more likely.

# How to apply

- A fake builds what the real system holds in advance before the call: the
  published keys and their assertions exist before any message is written.
  If the fake must build them later, pass the payload's own time as `now`.
- When a flake looks like order dependence, first look for two clocks read
  in different places, each truncated, with a check that orders them.
- To prove a suspected time-boundary flake, inject a wait to the next whole
  second between the two clocks, for example
  `await asyncio.sleep(1 - time.time() % 1 + 0.01)` at the start of the
  fake. The flake becomes a deterministic failure with the gate's exact
  error, and the same injection then proves the fix. This is the
  boundary-crossing form of the latency injection in
  [elapsed time is a test input](elapsed-time-is-a-test-input.md).

# Limits

The mechanism is specific to second-truncated contract times. The general
rule covers any two independently read clocks with an ordering check.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/fakes-must-not-mint-time-after-the-message.md. Task aweb-aeai.
Checked by the harvester: the `created_at > now` refusal in
`awid/src/awid/e2ee_keys.py` on aweb main 90519b0d2, and commit 11bc96c5a on
the source's aeai branch (not on main as of 2026-11-27), which builds both
identities before the send in two tests of
`server/tests/test_mcp_mail_chat.py`. The forced-crossing runs before and
after the fix and the single-test pass are source-reported.
