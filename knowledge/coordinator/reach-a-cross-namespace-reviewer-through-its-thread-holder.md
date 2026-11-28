---
type: Lesson
title: Reach a cross-namespace reviewer through its thread holder
description: A local team identity cannot address a reviewer whose address lives in another namespace, and a same-named roster seat is not proof that it is the same reviewer; at the first routing, ask the seat that already holds the reviewer's review thread to relay the full request and bring the verdict back.
tags: [review, routing, messaging, identity]
timestamp: 2026-11-28
---

A reviewer's address that resolves only within its own namespace cannot be
reached from a coordinator identity in another team. In one case, a reviewer
seat in the oats namespace was named in the briefing as reachable "by replying
in an existing thread". From the new coordinator identity:

- the address came back as "not a registered address";
- the implementer had no thread with the reviewer, because its earlier ACKs
  had arrived through another coordinator's relay;
- the directory lookup returned 404;
- a roster seat with a similar name never answered.

The review sat for most of a day. Once asked, the coordinator that held the
thread relayed the request within minutes. The reviewer confirmed that its
address resolves only within its own namespace, and its ACK came back by the
same relay.

## How to apply

- When a briefing says a reviewer is reachable only in an existing thread,
  find out at the first routing which seat holds that thread. Ask that seat
  to relay the request and the verdict. Relaying is routing; it does not ask
  that seat to decide anything.
- A similar name on the roster is not identity. Ask the seat to confirm who it
  is, and do not wait on it meanwhile.
- Do not spend effort on directory lookups or guessed aliases for an address
  in another namespace.
- Paste the full request, with the diff, into the relay so that the reviewer
  needs nothing else. This applies
  [review requests carry their content](review-requests-carry-their-content.md)
  to relays.

It rests on one case so far.

Evidence: OKF proposal from coordinator/approval-service, 2026-11-28;
notes/cross-namespace-reviewer-is-reached-through-its-thread-holder.md.
