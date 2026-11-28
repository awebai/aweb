---
type: Decision
title: Listing recovery is row-local; broken local key state fails the identity
description: In mail and chat listings an undecryptable row stays as a blank placeholder with a client-derived decrypt_error and is never acted on, while exact reads, transport, custody and service errors still fail; local encryption key state that exists but cannot load fails reads and encrypted sends for the whole identity. Ruled; placeholders are on a branch, the identity-level failure is released in aw-v1.36.59.
tags: [decision, e2ee, aw-cli, mail, chat, decryption]
timestamp: 2026-11-28
---

**Status (verified 2026-11-28 at aweb main fbfa65f22):** ruled by the protocol
owner. The placeholder behaviour is on the source's branch (c4ec1f8a4) and not
on main. The identity-level failure is released: 4e8972c49 is on main and
first released in aw-v1.36.59, and
`server/tests/test_chat_alias_reaches_teammate.py`
(`test_a_chat_read_whose_encryption_key_cannot_load_says_so`) pins it.

# Decision

**One undecryptable row does not fail a listing.** This covers the mail inbox,
the conversation view, chat history and chat pending. An undecryptable row
stays as a placeholder:

- It keeps its position and its ids. Its content is blank.
- It carries `decrypt_error`: `encryption_key_missing` when the key its wrap
  names is unavailable, otherwise `decrypt_failed`. The client derives the
  code itself and discards any value the server supplies.
- It is never auto-acked. It is never a reply target, a verified sender or
  prompt content.

**What still fails:**

- Exact reads of one message stay typed failures.
- Transport, cancellation, custody and service errors fail the whole listing.
- Local encryption key state that exists but cannot load is an
  identity-level failure. Mail and chat reads fail with the reason, and
  inherited encrypted sends fail rather than falling back to plaintext.

# Why

The placeholder is for one row that this identity cannot open, such as mail
wrapped to a lost archived key. A broken active key is a different condition:
every read would degrade silently, and sends could leak plaintext. A change
under this task first widened "keep going" from one row to the whole identity,
contradicting the released contract, and was reverted. Making reads work with
a broken active key would need its own contract review, with separate read and
encrypted-send behaviour.

How that regression got through review is
[a CLI change is not verified by the CLI suite](/aweb-protocol-expert/lessons/a-cli-change-is-not-verified-by-the-cli-suite.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-e2ee-rotation, 2026-11-28; no backing note.
Rulings are source-reported: protocol owner 183af2da, and bcdade7b, which
confirmed the setup boundary at b639fb191. The harvester checked the commits,
the release tag and the pinning test.
