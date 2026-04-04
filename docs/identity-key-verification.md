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

2. **Consistency checks**
   - Require `log_head.new_did_key == body.current_did_key`.
   - Require `log_head.seq >= 1`.
   - If `log_head.seq == 1`:
     - Require `log_head.prev_entry_hash == null`.
     - Require `log_head.operation == "create"`.
   - If `log_head.seq > 1`:
     - Require `log_head.prev_entry_hash` is present and hex.

3. **Reconstruct canonical entry payload bytes**
   - Build the payload object exactly as in “Log-head verification payload” above.
   - Serialize with canonical JSON rules.

4. **Verify `entry_hash`**
   - Compute `computed_entry_hash = sha256(payload_bytes)` (hex).
   - Require `computed_entry_hash == log_head.entry_hash`.

5. **Verify signature**
   - Verify Ed25519 signature `log_head.signature` over `payload_bytes` using the public key extracted from
     `log_head.authorized_by` (a `did:key`).
   - If verification fails → `HARD_ERROR`.

6. **Cache monotonicity / regression checks (equivocation detection within a single client)**
   - If cache exists:
     - If `log_head.seq < cached_seq` → `HARD_ERROR` (regression).
     - If `log_head.seq == cached_seq` and `log_head.entry_hash != cached_entry_hash` → `HARD_ERROR` (split view).
     - If `log_head.seq == cached_seq + 1` and `log_head.prev_entry_hash != cached_entry_hash` → `HARD_ERROR` (broken chain).
     - If `log_head.seq > cached_seq + 1` → `OK_DEGRADED` (seq gap: the head verifies cryptographically but append-only continuity from the cached head cannot be proven without fetching `/log`).

7. **Return**
   - If all checks pass → `OK_VERIFIED` and update cache with the new head.
   - Only update cache on `OK_VERIFIED`, not on `OK_DEGRADED`.

### Notes on what this does and does not prove

- `OK_VERIFIED` proves:
  - `aweb` presented a log head whose signature verifies against a `did:key`
    embedded in the response.
  - The `entry_hash` is consistent with the payload.
  - This client’s observed history is append-only (no regressions) for this `did_aw`.
  - Monotonicity is **per-client only** — each client tracks its own cache and can detect regressions or split views against its own history.
- `OK_VERIFIED` does **not** prove:
  - That the server is globally consistent (other clients may see a different
    head without witnesses/checkpoints).
  - That intermediate entries between the cached head and the current head are valid (when `seq > cached_seq + 1`, the result is `OK_DEGRADED` — fetch `/log` to verify the full chain).

## How aw should use this result (recommended)

When receiving a message with `from_stable_id = did_aw`:

- Resolve `GET /v1/did/{did_aw}/key` and run the verification algorithm above.
- If result is `OK_VERIFIED`:
  - Treat `current_did_key` as `aweb`'s signed view of the current key.
  - If it conflicts with the message envelope’s `from_did`, treat as a hard identity mismatch (reject or quarantine).
- If result is `OK_DEGRADED`:
  - Continue operating with TOFU + rotation-announcement rules, but record
    that stable identity verification was degraded.
- If result is `HARD_ERROR`:
  - Treat as security relevant; do not update pins, surface a strong warning, and consider rejecting messages that
    rely on this stable identity until the operator resolves it.

## Test vectors

Interoperability vectors live in [vectors/](vectors/README.md):

- `vectors/message-signing-v1.json` (canonical message signing payloads)
- `vectors/stable-id-v1.json` (`did:key` -> `did:aw` derivation)
- `vectors/identity-log-v1.json` (log entry hashing + signing)
- `vectors/rotation-announcements-v1.json` (rotation announcement payload signing/chaining)
- `vectors/dns-txt-v1.json` (canonical `_awid` DNS TXT records and optional `registry=` declaration)
