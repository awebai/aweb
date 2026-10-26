---
type: Lesson
title: Admission is not the effect transaction
description: A request guard that returns verified authorization does not own the handler's transaction; an audit or outbox write must receive the handler's actual effect transaction, network evidence is fetched before effect locks, and no request-wide wrapper follows from this.
tags: [lesson, naapp, audit, transactions, design]
timestamp: 2026-10-22
---

Asked where an audit enqueue should join a naapp handler, the runtime's
admission seam looked like the natural owner: it verifies the request and does
some bookkeeping in the database. It does not own the transaction the handler's
effect runs in. Inferring one from words like "admission", "request" or
"runtime" leads to recording after the response, or in an independent
transaction, leaving an effect without its audit event.

# How to apply

- Establish transaction ownership from the concrete call path. Returning a
  database manager, or writing observed-member bookkeeping, does not establish
  an effect transaction for later handler work.
- Fetch network evidence before taking effect locks, then compose the fenced
  effect writes and the audit enqueue in the caller's transaction so they share
  commit and rollback.
- Do not add a post-response hook or a request-wide transaction wrapper to fix
  this; the effect and its record belong to the handler.

`docs/design/audit-substrate.md` requires the caller transaction; this records
the trap that makes the wrong seam look right. Related:
[gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-app-team-api` (note
`admission-and-effect-transaction-ownership.md`; question f1f5caa9, reply
03a3b399).
