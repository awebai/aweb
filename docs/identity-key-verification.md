# aw ↔ aweb: verifying `GET /v1/did/{did_aw}/key` (`log_head`)

This document specifies how an `aw` client or any other verifier should
validate the stable-identity response from OSS `aweb`:

- `GET /v1/did/{did_aw}/key`

The goal is to make `/key` responses **cryptographically checkable** without
requiring the verifier to fetch the full `GET /v1/did/{did_aw}/log`, while
remaining honest about current limits (no global transparency yet).

## Scope

- Verifying the `aweb` `/key` response and its `log_head`
- Cache rules and failure modes (what is a “hard error” vs “degraded trust”)

Not in scope:
- DID/key rotation announcements in messages (`rotation_announcement(s)`)
- Full transparency / witness checkpointing

## Response shape (normative)

`GET /v1/did/{did_aw}/key` returns:

```json
{
  "did_aw": "did:aw:...",
  "current_did_key": "did:key:z...",
  "log_head": {
    "seq": 2,
    "operation": "rotate_key",
    "previous_did_key": "did:key:z...",
    "new_did_key": "did:key:z...",
    "prev_entry_hash": "hex...",
    "entry_hash": "hex...",
    "state_hash": "hex...",
    "authorized_by": "did:key:z...",
    "timestamp": "2026-06-01T12:00:00Z",
    "signature": "base64..."
  }
}
```

All fields are additive over the minimal mapping (`did_aw`, `current_did_key`). Clients MUST ignore unknown
fields.

## Canonicalization + crypto (normative)

### Canonical JSON

Canonical JSON is defined as:
- lexicographic key sort
- compact separators `,` and `:`
- literal UTF-8 (no `\uXXXX` escaping for non-ASCII)
- minimal JSON string escaping (only what JSON requires: `"`, `\`, and control characters)

This MUST be compatible with the message-signing canonicalization described in `sot.md` §4.2.

### Signature encoding

Ed25519 signature bytes encoded as base64 (RFC 4648) with **no `=` padding**.

Implementations must treat the no-padding form as canonical.

### Log-head verification payload

Given a `/key` response for stable identity `did_aw`, the verifier MUST reconstruct the log-entry payload bytes
for the head entry using the fields from `log_head` plus `did_aw`:

```json
{
  "authorized_by": "did:key:z...",
  "did_aw": "did:aw:...",
  "new_did_key": "did:key:z...",
  "operation": "rotate_key",
  "prev_entry_hash": "hex-or-null",
  "previous_did_key": "did:key:z...-or-null",
  "seq": 2,
  "state_hash": "hex...",
  "timestamp": "2026-06-01T12:00:00Z"
}
```

Rules:
- `prev_entry_hash` is `null` for `seq=1`, otherwise a lowercase hex string.
- `previous_did_key` is `null` for `operation=create`, otherwise a `did:key`.
- `entry_hash = sha256(canonical_json(payload))` (lowercase hex).
- `signature` is Ed25519 over the canonical payload bytes, verified offline against `authorized_by` (a `did:key`).
 - `timestamp` is RFC 3339 / ISO 8601 with timezone, second precision (e.g. `YYYY-MM-DDTHH:MM:SSZ`).
   Clients SHOULD treat fractional seconds as non-canonical and reject them when constructing signed payloads.

## Verification algorithm (normative)

### Inputs

- `did_aw` (the stable identity being queried)
- HTTP response JSON body
- Local cache entry, if present:
  - `cached_seq` (integer)
  - `cached_entry_hash` (hex)
  - `cached_state_hash` (hex)
  - `cached_current_did_key` (did:key)
  - `cached_fetched_at` (timestamp)

### Output categories

- `OK_VERIFIED` — `/key` mapping and `log_head` verify cryptographically
- `OK_DEGRADED` — response is usable but cryptographic verification could not be performed
- `HARD_ERROR` — response is inconsistent, malformed, or indicates equivocation/regression

### Steps

1. **Basic shape + syntax checks**
   - Require `body.did_aw == did_aw`.
   - Require `body.current_did_key` is a syntactically valid `did:key` (Ed25519).
   - If `log_head` is missing → return `OK_DEGRADED` (treat like “unverifiable mapping”).

2. **Consistency + authorization checks**
   - Require `log_head.new_did_key == body.current_did_key`.
   - Require `log_head.seq >= 1`.
   - If `log_head.seq == 1` (genesis):
     - Require `log_head.prev_entry_hash == null` and `log_head.previous_did_key == null`.
     - Require `log_head.operation` is `create` or `register_did`.
     - Require `log_head.authorized_by == log_head.new_did_key` — genesis is
       self-authorizing (the identity holder signs its own registration).
     - Require `did_aw == derive_did_aw(log_head.new_did_key)` — the stable
       identity MUST be the canonical derivation of the genesis key, so a forged
       genesis cannot claim an unrelated `did:aw`.
   - If `log_head.seq > 1` (rotation):
     - Require `log_head.operation == "rotate_key"`.
     - Require `log_head.prev_entry_hash` is present and hex.
     - Require `log_head.previous_did_key` is present and a valid `did:key`.
     - Require `log_head.authorized_by == log_head.previous_did_key` — a rotation
       is authorized only by the retiring key signing its own replacement.

3. **Reconstruct canonical entry payload bytes**
   - Build the payload object exactly as in “Log-head verification payload” above.
   - Serialize with canonical JSON rules.

4. **Verify `entry_hash`**
   - Compute `computed_entry_hash = sha256(payload_bytes)` (hex).
   - Require `computed_entry_hash == log_head.entry_hash`.

5. **Verify `state_hash`**
   - Compute `computed_state_hash = sha256(canonical_json({"current_did_key":
     log_head.new_did_key, "did_aw": did_aw}))` (lowercase hex). This is the
     `identity_state_hash` produced by `aweb`.
   - Require `computed_state_hash == log_head.state_hash`. A valid signature over
     a payload whose `state_hash` does not equal the canonical state MUST NOT pass.

6. **Verify signature**
   - Verify Ed25519 signature `log_head.signature` over `payload_bytes` using the
     public key extracted from `log_head.authorized_by` (a `did:key`). Because of
     step 2, `authorized_by` is bound to the genesis key (`seq==1`) or the
     retiring key (`seq>1`) — it is not a free-floating key the response chooses.
   - If verification fails → `HARD_ERROR`.

7. **Cache monotonicity / continuity checks (equivocation detection within a single client)**
   - If cache exists:
     - If `log_head.seq < cached_seq` → `HARD_ERROR` (regression).
     - If `log_head.seq == cached_seq` and `log_head.entry_hash != cached_entry_hash` → `HARD_ERROR` (split view).
     - If `log_head.seq == cached_seq + 1`:
       - If `log_head.previous_did_key != cached_current_did_key` → `HARD_ERROR` (key discontinuity).
       - If `log_head.prev_entry_hash != cached_entry_hash` → `HARD_ERROR` (broken chain).
     - If `log_head.seq > cached_seq + 1` → `OK_DEGRADED` (seq gap: the head is
       internally consistent but append-only continuity from the cached head
       cannot be proven without fetching `/log`).

8. **Anchoring gate + return**
   - `OK_VERIFIED` requires the head to be *anchored*: either it is genesis
     (`seq==1`, self-anchored via its `did:aw` derivation) or it is adjacent to a
     previously verified head (`seq == cached_seq` or `cached_seq + 1`, having
     passed the continuity checks above).
   - If `log_head.seq > 1` and there is **no cached head** (or a seq gap), the
     transition from genesis cannot be proven from a single head → `OK_DEGRADED`.
     Fetch `GET /v1/did/{did_aw}/log` and verify the full chain from genesis
     before trusting it.
   - Otherwise → `OK_VERIFIED` and update cache with the new head.
   - Only update cache on `OK_VERIFIED`, not on `OK_DEGRADED`.

### Full-log verification (`GET /v1/did/{did_aw}/log`)

When a single head is not anchored (unanchored `seq>1`, or a seq gap from the
cached head), verify the whole log:

- The log MUST start at a valid genesis entry (step 2, `seq==1` rules).
- Each subsequent entry MUST satisfy the `seq>1` rules and chain to its
  predecessor: `seq` increments by one, `prev_entry_hash == predecessor.entry_hash`,
  and `previous_did_key == predecessor.new_did_key`.
- Every entry’s `state_hash`, `entry_hash`, and signature MUST verify (steps 4–6).
- The final entry’s `new_did_key` MUST equal `body.current_did_key`.

Only a fully genesis-anchored log verification (or a head adjacent to such a
verified head) yields `OK_VERIFIED`.

### Notes on what this does and does not prove

- `OK_VERIFIED` proves:
  - The transition is authorized by the correct key: genesis is self-signed by
    the key being bound, and each rotation is signed by the retiring key it
    replaces. `authorized_by` is bound to that key, not chosen freely by the
    response.
  - `did_aw` is the canonical derivation of the genesis key, and every entry’s
    `state_hash` and `entry_hash` match the canonical payload.
  - The head is anchored to genesis — either it *is* genesis, or it continues an
    unbroken `seq`/`prev_entry_hash`/`previous_did_key` chain from a previously
    verified head (or, via `/log`, from genesis directly).
  - This client’s observed history is append-only (no regressions) for this `did_aw`,
    **across restarts**: the highest verified `seq` and its `entry_hash` are
    persisted with the pin (`log_seq`, `log_entry_hash`) and restored before
    verification. A served log that is behind that checkpoint, or that does not
    *contain* the checkpoint entry, is refused — so neither a truncated prefix
    nor a fork that dropped the entry can roll the identity back to a retired
    key. The checkpoint only ever advances.
  - Monotonicity is **per-client only** — each client tracks its own checkpoint and can detect regressions or split views against its own history.
- `OK_VERIFIED` does **not** prove:
  - That the server is globally consistent (other clients may see a different
    head without witnesses/checkpoints).
  - **Anything about which address this identity may claim.** The log proves
    `did:aw → did:key`; it never proves `address → did:aw`. An attacker who
    legitimately owns their own `did:aw` has a wholly valid log, so
    `OK_VERIFIED` is not authority to take over an address pinned to a
    different stable identity. Moving an address between stable identities
    requires a replacement announcement signed by the namespace controller
    named in the address's `_awid` DNS TXT record; absent that proof the
    existing pin stands and the result is `identity_mismatch`.
- `OK_DEGRADED` means verification could **not** be completed (missing
  `log_head`, or an unanchored `seq>1` head, or a seq gap). It is **not** a
  trusted result: it MUST NOT replace or overwrite a pinned key. It may prompt a
  full `/log` fetch, but on its own it can never authorize a pin change.

## How aw should use this result (recommended)

When receiving a message with `from_stable_id = did_aw`:

- Resolve `GET /v1/did/{did_aw}/key` and run the verification algorithm above.
- If result is `OK_VERIFIED`:
  - Treat `current_did_key` as `aweb`'s signed view of the current key.
  - If it conflicts with the message envelope’s `from_did`, treat as a hard identity mismatch (reject or quarantine).
  - Only this result — a genesis-anchored verification — may replace a stale
    TOFU-pinned key for this `did_aw`.
- If result is `OK_DEGRADED`:
  - Continue operating with TOFU + rotation-announcement rules, but record
    that stable identity verification was degraded.
  - MUST NOT replace or overwrite a pinned key on the strength of this result.
    A degraded result may only trigger a full `/log` fetch to attempt a genesis
    -anchored verification.
- If result is `HARD_ERROR`:
  - Treat as security relevant; do not update pins, surface a strong warning, and consider rejecting messages that
    rely on this stable identity until the operator resolves it.

## Test vectors

Interoperability vectors live in [vectors/](vectors/README.md):

- `vectors/message-signing-v1.json` (canonical message signing payloads)
- `vectors/stable-id-v1.json` (`did:key` -> `did:aw` derivation)
- `vectors/identity-log-v1.json` (log entry hashing + signing)
- `vectors/identity-log-negative-v1.json` (verifier authorization / state-hash / anchoring outcomes, shared Go↔TS)
- `vectors/rotation-announcements-v1.json` (rotation announcement payload signing/chaining)
- `vectors/dns-txt-v1.json` (canonical `_awid` DNS TXT records and optional `registry=` declaration)
