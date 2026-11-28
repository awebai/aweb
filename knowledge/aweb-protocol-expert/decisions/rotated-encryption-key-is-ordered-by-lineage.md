---
type: Decision
title: A rotated encryption key is ordered by lineage, not timestamp
description: Rotation must produce an assertion strictly newer than its predecessor, and the newest-key projections rank a key below any eligible successor its authenticated rotation lineage proves; readers open the archived key the wrap names; a server check that wraps target the recipient's current key was rejected. Ruled; the client half is on a branch, the projection half not implemented.
tags: [decision, e2ee, encryption-keys, rotation, awid, aw-cli]
timestamp: 2026-11-28
---

**Status (verified 2026-11-28 at aweb main fbfa65f22):** ruled by the
coordinator and the protocol owner. Part A (client) is on the source's branch
(e63afad24), not on main. Part B (server and AWID) is ruled for a separate
release and not implemented. On main, all three newest-key projections still
order by `assertion_created_at DESC, not_before_at DESC, encryption_key_id DESC`
(`server/src/aweb/routes/agents.py`, `server/src/aweb/routes/messaging.py`,
`awid/src/awid_service/routes/did.py`), and the client truncates assertion
times to the second (`cli/go/awid/e2ee_keys.go`).

# The defect

Encryption-key assertions carry whole-second times. A rotation in the same
second as its predecessor is therefore a tie between two keys, and the key id
hash breaks it. Senders get the superseded key about half the time. That goes
against the contract's "New sends use the newest valid key"
(`docs/e2e-messaging-contract.md`, "Key Loss And Rotation"). The real "newer"
authority is the rotation link, `previous_encryption_key_id`.

# Decision

- **A, client:** rotate waits, bounded and cancellable, until its whole UTC
  second is after the predecessor's signed `created_at`. It never
  future-dates. If the clock cannot advance within the bound, it refuses
  before creating, activating or publishing any key.
- **B, server and AWID, a separate release:** a key ranks below any eligible
  candidate that its authenticated rotation lineage proves is a successor.
  This holds transitively through ineligible intermediates (K1 to K2 to K3
  with K2 ineligible: K3 beats K1). Cycles get a bounded rule, and unrelated
  keys get a deterministic fallback. The same rule applies at all three
  sites: the server roster, the messaging participants and AWID DID
  resolution. B exists because released clients have already published
  same-second rotations that A cannot fix.
- **Readers** open the archived private key that the envelope's wrap names,
  by key id. They never try keys in turn, and they never check expiry when
  reading old mail.

A future change to key publication or projection must not reintroduce a
timestamp-only "newest".

# Rejected

The server could refuse any wrap whose key id is not the recipient's current
key. This was rejected because the contract allows two cases that use an
older key that is still valid and that the recipient reads from its archive:
sends still in flight across a rotation, and replies that continue an
addressless conversation (`docs/e2e-messaging-contract.md`, the reply
continuity rules before "Rotation publishes a new assertion").

# Lesson from the investigation

Failure after rotation had two independent causes. The deterministic one was
a reader that loaded only the active key. The intermittent one was the
same-second tie. One passing real-stack run had been taken to clear the
sender side, and an eight-run loop then failed 3 of 8. When a hypothesis
concerns timing or ordering, repeat the real-stack test before ruling a side
out, and correct any record you have already sent. After A, the same loop
passed 12 of 12 (source-reported).

This is consistent with
[key authority history spans every path to the key](/aweb-protocol-expert/decisions/key-authority-history-spans-every-path.md):
rotation uses a new key id.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-e2ee-rotation, 2026-11-28; notes/rotation-failure-has-two-causes.md.
Rulings are source-reported: coordinator 0af57595 and abf7c597, protocol owner
183af2da and 4e9f308e. The run counts are source-reported. The projection
order, the truncation and branch commit e63afad24 were checked by the
harvester.
