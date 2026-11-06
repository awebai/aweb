---
type: Decision
title: Stream room authority is re-proved lazily
description: A long-lived agent stream emits room content only on a successful authority check younger than 60 s, re-proved only when there is content to emit, and a failed check emits nothing; an eager 60 s timer was rejected. Accepted; on main and in server-v1.27.47.
tags: [decision, event-stream, rooms, authorization, performance]
timestamp: 2026-11-04
---

Acknowledged by the security and identity reviewer on 2026-11-04 (design ACK e7aa29ec, thread c3299855).

**Status (verified 2026-11-06):** accepted; on main (43528d6b9) and first
released in server-v1.27.47.

# Decision

- Room content is emitted only on a successful authority check younger than
  60 s.
- The check runs at stream open and again only when there is room content to
  emit and the last proof is older than 60 s.
- A failed check emits nothing.

# Rejected

An eager 60 s timer gives the same freshness invariant but does registry work
on idle streams, which is the load the
[push-driven stream](/aweb-protocol-expert/decisions/agent-event-stream-is-push-driven.md)
removes. Per-tick re-verification was the earlier form and was removed for the
same reason.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/room-authority-lazy-60s.md.
