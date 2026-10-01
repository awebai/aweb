---
type: Lesson
title: Recover work from action receipts
description: A message marked read can still contain unfinished work; recover exact messages and reconcile side effects before retrying.
timestamp: 2026-10-01
---

Delivery, reading and completing a request are separate events. After a crash,
compaction or handover, use exact message IDs or paginated history covering the
uncertain interval, then compare each request with tasks, working state and
receipts for its side effects. An empty unread inbox cannot establish that
already-presented work was completed. Check an earlier push, sent reply or task
update before repeating it.

A pending-chat preview is also a summary, not an unread inventory: the latest
message may be yours while an earlier incoming request remains unread. Conversely,
a broker hint can outlive the work it describes. Fetch the authoritative item and
check its history; neither replayed hints nor a cached unread count justify sending
a duplicate reply. Use the deployment's delivery mechanism and task-boundary
checks rather than inventing an idle polling loop.

The September 29, 2026 delivery proof recorded server read state before the
recipient began commands. Archived session evidence confirms that ordering. This
refines the distinction in [delivery receipts and stream health](../aweb-protocol-expert/lessons/delivery-receipts-and-stream-health.md): a host's accepted presentation still does not prove action completion.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `presentation-ack-is-not-action-completion.md`, `pending-chat-preview-is-not-unread-inventory.md`, `comms-at-task-boundaries.md`, `broker-duplicate-hint-after-chat-reply.md`, `broker-unread-is-a-high-water-mark.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
