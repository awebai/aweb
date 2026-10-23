# Core hook signer unavailable

Status: proposed contract correction assigned by the secrets coordinator on
2026-10-23 (`f8904485-581c-49ed-8f40-ce224147c99b`), with the smaller mechanism
ruled in `886aacd3-832e-475d-afd6-07c2ceaa4038`. It is separate from the
[terminal delivery amendment](hook-terminal-delivery.md). Producer and receiver
fit, independent review and Athena precede acceptance. This document specifies
behavior; it does not establish an implementation or a production incident.

## Authority and failure policy

The controller authorizes a hook binding through the existing owner act. The
operator supplies the separate core hook signer. A valid owner act, working
member credential or installed target does not supply that signing authority.
The core signer retains its published provenance and half-open validity window,
`[valid_from, valid_until)`. Warnings grant no grace, and the controller or an app
key never substitutes for an unavailable core key.

Activation of a **registration for `post-mutation-hook`** requires a currently
valid, configured core signer. Its absence or expired validity returns
`409 core_hook_producer_unconfigured`, leaving the binding pending and the
owner-act nonce unconsumed. Existing owner verification and exact subject checks
still apply. This is the coordinator's explicit readiness rule, rather than a
new owner-act field, manifest purpose or source of activation authority. It
adds no corresponding gate to other registrations or app productions, and the
optional `hook-terminal-receipt` purpose remains optional.

A core mutation, including owner revocation, does not fail merely because the
core signer is unavailable. Normal authorization and local transaction failures
still refuse as before. A malformed configured private key, unsafe key file or
mismatched published key remains a startup failure under decision 10. An
unconfigured producer and a signer that becomes unavailable after startup are
covered by the accounting below. In particular, existing active registrations
may survive a restart with the producer unconfigured; the rule is not limited
to one expiry trigger. This is contract scope, not evidence of an observed
production failure.

With a valid signer, the ordinary signed event and mutation still commit
together. When a fresh view shows no eligible registration, the existing core
rule owes no ordinary event. A formerly active target's terminal obligation
is accounted separately below, including its existing original-hook/pad
exception. The rule creates no target requirement for ordinary coordination.

## Atomic missing-production reservation

When an event is owed but the signer is unavailable, the shared kit performs
one local operation inside the effecting mutation's transaction:

1. Reserve the next `producer.seq` in the existing **(producer, team, hook)**
   namespace, using the same sequence lock/fence as ordinary signed enqueue.
   The logical firing spends exactly one sequence number, regardless of its
   number of target registrations. Retain the core origin identifying that
   producer; do not infer continuity across a server move.
2. Persist a typed `missing_production` accounting record with that reservation:
   namespace, reserved sequence, occurrence time, bounded signer-unavailable
   reason and the old binding IDs to which the firing was owed. It contains no
   private key, raw request, credential value or replacement signed envelope.
3. Commit the reservation, record and mutation together. Rollback removes all
   three. Failure of the local accounting write is a local transaction failure;
   signer or delivery availability is not an additional commit gate.

Use the existing shared outbox/sequence tables, with a new ordered kit migration
for the typed local record. Core applies the kit migrations, rather than copying
SQL or creating its own ledger. The type must be enforced by storage and shared
APIs: a missing-production row is not a signed `OutboxEvent` with an empty or
fabricated signature. It cannot be materialized, delivered, retried, acknowledged,
counted as received, or cancelled as an ordinary delivery. Every shared scanner
that handles materialization, transport, backlog, cancellation, receipts or
ordinary delivery faults must distinguish that type. Keep its sequence and
operator accounting after normal event drains; never purge it as delivered.
Any storage alternative must demonstrate these same invariants before review.

The existing counters continue after reservations. A recovered signer uses the
next sequence for a new effect. It never fills an old hole, re-signs a missed
mutation, or converts the accounting record into a wire event. There is no new
catalog mutation type, recovery-signing worker, explanation idempotency path or
receiver classification. Existing signed event and delivery bytes stay intact.
Ordinary queued deliveries retain their existing key-window and retry rules;
key expiry supplies no permission to sign a fresh retry with an expired key or
to rewrite immutable event bytes.

## What a receiver can establish

A receiver can establish an unexplained sequence hole only from authenticated
evidence in the same producer/team/hook namespace and its applicable binding
interval. For example, valid events at sequence 40 and 43 can expose missing
41 and 42. The local reservations alone are not remote evidence and are never
accepted as unsigned hook deliveries or fabricated chain entries. Existing
producer-specific signed cancellation records retain their own exact scope;
these production losses have no such explaining record and remain unexplained.

A **trailing loss without later authenticated evidence cannot be proved remotely**
from an absent message. The operator's durable state carries that outstanding
loss. The same caution applies to an unanchored prefix: a receiver must not
invent a starting sequence or binding interval. Key restoration does not erase
the local missing-production count or change an unexplained hole into a signed
explanation. A receiver reporting no observed internal hole has not proved the
absence of trailing loss.

## Terminal obligations

When an end occurs without a usable signer, containment still takes effect in
that transaction. Preserve the previously active target's exact old binding,
installation, generation, digest, endpoint, receipt-key authority, end evidence
and cancellation accounting, under the existing terminal transaction/fence.
Reserve the sequence for its owed logical terminal firing once. Record its
terminal obligation as `terminal_reconciliation_required`, surfaced to both the
owner and operator. A never-active registration receives no terminal obligation.

There is no valid terminal event/capsule to dispatch or acknowledge in this
case. The [terminal contract](hook-terminal-delivery.md#key-windows-and-authority-changes)
requires the historical signer window to cover the end/event time and binds
the capsule to the exact signed event. This correction grants no retrospective
signing, backdated validity, retired-key reuse, reroute or new-generation key
substitution. A missing-production reservation, diagnostic, later ordinary event
or cancellation summary never counts as `hook_binding.revoked` or a signed
binding seal. Key restoration leaves this unfulfilled final-entry obligation
outstanding; neither a successful revocation nor an observed later sequence
proves terminal delivery. The security cut-off commits immediately and completion
is never faked.

Valid terminal events/capsules already committed before signer loss retain all
existing rules, including their distinct current transport signer and stored
receiver acknowledgement. This accounting rule changes none of their hashes,
key windows, endpoint pinning, dedup, seals or retry authority.

## Minimum operator diagnostics

Emit one structured signer-unavailable fault per failure-state transition, with
component, bounded reason, configured `kid` when present and `valid_until` when
known. A new process may report its initial unavailable state. Do not log key
material, event contents or credentials. The durable records provide the pending
missing-production count, oldest occurrence and outstanding terminal count for
operator inspection through the existing store; no new endpoint is introduced.
Owner-facing fault reporting must also retain the outstanding terminal state.
These diagnostics are operational facts, not producer-signed event evidence.

At startup and in existing producer maintenance, warn when the configured
`valid_until` is within a configurable positive lead time, **seven days by
default**. An unavailable key produces the fault above; a key without an end
has no expiry warning. Suppress repeated warnings within a warning state, while
reporting a changed key/deadline or a new process normally. The lead is an
operator diagnostic only: it neither refuses an otherwise valid activation nor
extends any validity or request-verification window.

## Evidence and implementation acceptance

The coordinator's rulings above specify the correction. The source question
arose on an unshipped S2 candidate; source inspection alone is not a production
cause or runtime reproduction. Tests must first reproduce the actual candidate
HTTP/key/containment case, including valid-key controls, and be committed and
independently read before a product fix. Keep author execution evidence distinct
from independent source review.

This delta changes no catalog payload, enum, event signature or signed vector.
It preserves the scoped [decision-93 evidence and stop rule](hook-terminal-delivery.md#deliberate-catalog-re-freeze-and-implementation-evidence),
without claiming a fresh deployment inventory or creating another version.
Published clients continue to receive the same signed shapes. The newly
specified activation readiness refusal must be reviewed explicitly as part of
this correction; it must not be presented as an existing implementation rule.

Shared implementation acceptance covers reservation/event sequence serialization,
rollback of mutation and reservation, scanner exclusion, zero unsigned delivery,
restart with an unavailable signer and existing registrations, runtime expiry,
valid-key controls, unchanged no-target behavior, subsequent signed sequence
holes and honest trailing-loss reporting. Terminal cases cover end with no
other target, its pad/original-hook exception, preserved old receipt authority,
owner/operator visibility and rejection of fake completion. Diagnostics cover
expiry-warning boundaries/configuration and absence of authority grace. Producer
and Logs fit precede independent review and Athena, which explicitly checks the
outstanding-terminal and unexplained-gap guarantees. Production activation waits
for the reviewed shared/S2/L2 implementation and its focused/real-path evidence.
