---
type: Lesson
title: Preserve capability boundaries through adapter changes
description: A transport or adapter refactor must not infer mutation or custody authority from permission to read.
timestamp: 2026-10-01
---

Read, acknowledge, sign, decrypt and administer are separate capabilities.
Replacing a wake hint with full-content delivery must preserve those distinctions,
including grants that can fetch a message but cannot acknowledge it. Where an
adapter cannot perform an authorized acknowledgment, represent that limit and
retain its supported delivery deduplication behavior rather than broadening the
grant silently.

A session signing key and the represented subject are also different identities.
Request authentication, authorship verification and encrypted-history access need
separate proofs. Hosting a route does not establish who holds decryption keys;
a ready custody service does not prove that a freshly minted grant can use it.
Exercise that actual grant and consumer path.

September 2026 adapter and custody reviews established these as compatibility
questions across several layers. Keep exact scope maps and supported command
matrices in current source and contract documentation, not in harvested release
snapshots. Route changes to those contracts for protocol review. This lesson
complements [delivery receipt boundaries](../aweb-protocol-expert/lessons/delivery-receipts-and-stream-health.md) without changing authorization policy.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `grant-delivery-does-not-imply-ack-authority.md`, `grant-custody-inner-metadata-and-continuity.md`, `multiteam-identity-and-wake-boundaries.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
