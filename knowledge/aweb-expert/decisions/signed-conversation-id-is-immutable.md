---
type: Decision
title: A signed conversation id is immutable
description: The server never stores or moves a message under any conversation id other than the one in the sender's signed payload; a fix that would merge into an existing thread must let the client find that thread before it signs, or refuse in a structured way.
tags: [decision, messaging, signing, e2ee, conversations]
timestamp: 2026-10-23
---

Ruled binding by the security reviewer on 2026-10-23 ("no re-threading") and
confirmed by the OSS coordinator as binding on the design of the mail-send
fix-forward, when a server-side "merge into the existing conversation" repair
was proposed.

# Decision

- The client signs the conversation id, including a freshly minted one.
  Recipients compare the signed id with the stored one, and end-to-end key
  wraps bind it. The server therefore never stores a message under a different
  conversation id and never rewrites one.
- A repair that wants a message in an existing thread is safe only when the
  signed id already equals the target. Otherwise the server either returns a
  structured refusal the client can act on, or the message starts a new
  conversation under its signed id.
- The way to reach the existing thread is to let the client find it before
  signing, not to re-thread after.

# Rejected

Server-side re-threading: it breaks signature verification and decryption at
the recipient, and it would let the server move signed messages between
threads.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (note
`signed-conversation-id-is-immutable.md`; security reviewer 96b59cfe,
coordinator 5bedc353). Verified against main f8f627fb9: the message route
refuses a signed payload that does not bind the existing conversation id.
