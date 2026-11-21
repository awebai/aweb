---
type: Lesson
title: Diagnose a red real-path test's world before the product; an E2EE test ends with the recipient reading
description: A red real-path test is evidence about the product only if the world it built is one the product can produce, so print the served artifact beside the client's identity and keys before blaming either side; an end-to-end encryption test proves nothing until the intended recipient decrypts the plaintext through the product.
tags: [lesson, testing, e2ee, fixtures, diagnosis]
timestamp: 2026-11-19
---

Replacing mocks with real services (see [tests exercise the real
authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md))
does not by itself make a red a product failure. A real path can still fail on
state that only the fixture made.

# The rules

- **Check the world first.** When a real-path test goes red, first ask whether
  a user could reach the state the test built. Print the served artifact (for
  example, the envelope's delivery wrap key id) beside the client's identity
  and the keys it actually holds. Do this before diagnosing the server or the
  client. A state no user reaches is a fixture fault, and the fix belongs in
  the fixture, written the way the product would write it.
- **E2EE coverage means the recipient reads.** An encryption test is complete
  only when the intended recipient decrypts the plaintext through the product.
  A test that asserts only the sender's wire shape against a fake server can
  stay green while no recipient is able to read the message.

# Example

In aweb-adkq, the E2EE first-contact test failed with "not a recipient". It
looked like a product decrypt failure. The server fixture's actor helper
(`server/tests/chat_pair_support.py`) inserts an encryption key for every actor
by SQL. The test then published a second key with
`aw id encryption-key setup` in the same second. The actor now had two current
keys, a state no user reaches. The roster selects the current key
`ORDER BY assertion_created_at DESC, not_before_at DESC, encryption_key_id DESC`
(`server/src/aweb/routes/agents.py`). The timestamp has one-second precision,
so key-id order broke the tie. About half the time the sender was served the
fixture key, which the reader's CLI home did not hold, and the client correctly
refused to decrypt. The run on a dev VM that settled it compared two values.
The served envelope's wrap key id differed from the reader's only key. The fix
gives the CLI home the actor's one fixture key, stored the way the CLI stores
it.

The earlier fake-server Go test for the same flow asserted only what the sender
put on the wire. It never had the recipient read, so it could not have caught
an unreadable message.

# Elimination route

The incident's own causes belong in code, not here. The fixture fix is on the
source's review branch at 4e8972c496 (not yet reviewed, not on main at
ecb9d825a). The roster's one-second tie-break is filed as aweb-adla and is not
fixed. This lesson records the diagnosis order and the coverage bar, which no
check enforces.

Related: [acceptance must exercise the claimed
operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md) and
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-19; notes/fake-server-test-hid-unreadable-e2ee.md.
The fixture's SQL key insert and the roster's ORDER BY were checked against
aweb main at ecb9d825a. This rests on one incident.
