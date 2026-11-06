---
type: Decision
title: Stream wakes target the resolved identity
description: A mail or chat wake on the agent event stream goes to the delivery identity the write path resolved, never to a stored address field, so a stream subscribes only to its own DIDs; subscribing streams to predecessor identities was rejected. Accepted; on main and in server-v1.27.47.
tags: [decision, event-stream, wake, identity, succession, mail, chat]
timestamp: 2026-11-04
---

Ruled by the security and identity reviewer on 2026-11-04 in the push-driven stream design thread
(c3299855, ruling 17a306af, also acknowledged by the OSS coordinator in
d8e8baf0).

**Status (verified 2026-11-06):** accepted; on main (3a53b6800, with the
succession wake test b2cf880d1) and first released in server-v1.27.47. This
record does not show it running in production.

# Decision

- A wake for mail or chat is published to the identity the write resolved for
  delivery: the recipient row's `did_aw` and `did_key`, the chat session's
  participants, or the reader. It is never keyed by a stored address field
  such as `to_did`, `signed_recipient_did` or an envelope target.
- A stream therefore subscribes only to its own DIDs.

# Why

Mail can be stored addressed to a thread-local current `did_key` or to a
recorded-succession predecessor. A wake keyed by the stored field misses the
viewer's stream unless the stream also subscribes to every historical spelling
of its identity. Keying by the resolved delivery identity makes the
subscription set exactly the stream's own DIDs.

# Rejected

Subscribing streams to predecessor identities through the shared succession
helper. That helper still serves the mail snapshot only; it is not a
subscription source.

# How to apply

Any new write path that should wake a stream publishes to the identity it
resolved, and gets a wake-latency test; succession-addressed mail needs one of
its own. Related:
[the agent event stream is push-driven](/aweb-protocol-expert/decisions/agent-event-stream-is-push-driven.md),
[address history does not prove identity continuity](/aweb-protocol-expert/decisions/address-history-does-not-prove-identity-continuity.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/stream-wake-targets-resolved-identity.md.
