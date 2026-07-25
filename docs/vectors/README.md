# Protocol conformance vectors

This directory publishes **deterministic conformance vectors** for the OSS
`aweb` identity, continuity, and verification rules defined in:

- [aweb-sot.md](../aweb-sot.md) (Concepts section)
- [identity-key-verification.md](../identity-key-verification.md)

These vectors exist to prevent subtle cross-language drift (Python ↔ Go) in:
- Canonical JSON serialization
- Signature base64 encoding
- `did:key` ↔ public key parsing
- Stable ID derivation (`did:aw:`)
- audit-log entry hashing + signing

## Files

- `message-signing-v1.json`
  - Canonical message payload (UTF-8 bytes)
  - Expected Ed25519 signature (base64, **no padding**)
  - Includes variants with and without stable ID fields

- `identity-log-v1.json`
  - Canonical identity-only `register_did` and `rotate_key` envelope payloads
  - Expected identity-only `state_hash` inputs and hashes
  - Expected `entry_hash` (sha256 hex)
  - Expected Ed25519 signature (base64, **no padding**)

- `identity-log-negative-v1.json`
  - Shared DID-log verifier outcome vectors (positive + negative)
  - Each `cases` entry feeds a `log_head` (and optional `cached` head) to the
    verifier and asserts `expected_outcome`
    (`OK_VERIFIED` / `OK_DEGRADED` / `HARD_ERROR`)
  - `log_cases` feed full logs to the genesis-anchored chain verifier
  - Consumed byte-for-byte by the Go (`VerifyDidKeyResolution`) and TypeScript
    (`verifyDidKeyResolution`) verifiers to keep authorization, state-hash, and
    anchoring semantics aligned

- `identity-log-raw-wire-v1.json`
  - Carries complete JSON text rather than pre-decoded typed structures, so
    decoder-level cases such as fractional and unsafe sequence numbers remain
    expressible to every runtime
  - BOTH runtimes reject BOTH cases; there is no outstanding divergence here.
    They reject at different LAYERS, which the vector records as positive
    per-runtime expectations rather than as a note: for a fractional seq Go
    fails during typed JSON decoding (`seq` is an int field, so the value never
    reaches the verifier) while TypeScript's `JSON.parse` accepts it and the
    verifier's safe-integer guard rejects it. Above 2^53, 64-bit Go decodes the
    value and the verifier's safe-integer bound rejects it; 32-bit Go cannot
    represent it in `int` and fails during decoding

- `pin-store-raw-wire-v1.json`
  - Decode-level trust-store (`known_agents.yaml`) cases carrying RAW YAML wire
    text, so each runtime feeds the same on-disk bytes through its own
    load-and-validate path (Go `LoadPinStore`, TypeScript `PinStore.fromYAML`).
    Pre-decoded structures could not express a malformed document at all
  - Expectations are POSITIVE PER RUNTIME and include error substrings, so a
    case asserts WHY a document was rejected. Outcomes alone are not enough:
    two runtimes can reject the same input for different reasons, which reads
    as agreement while hiding a divergence
  - Three cases record a real, measured divergence: Go rejects non-string
    mapping keys while js-yaml coerces them to strings and TypeScript accepts.
    Not reachable through our own write path — `aw` is the sole writer.
    Tightening TypeScript is tracked separately

- `stable-id-v1.json`
  - `did:key` → stable ID derivation vectors

- `rotation-announcements-v1.json`
  - Canonical rotation-announcement payloads (single link + chaining)
  - Expected Ed25519 signatures (base64, **no padding**)

- `dns-txt-v1.json`
  - Canonical `_awid.<domain>` TXT record name/value pairs
  - Covers default public-registry records and explicit `registry=` declarations

## Encoding notes

- **Canonical JSON:** lexicographic key sort, compact separators, literal UTF-8 (no `\uXXXX` escapes).
- **Signatures:** Ed25519 signature bytes encoded as base64 (RFC 4648), no `=` padding.

## Validation

The backend test suite validates these vectors:

```bash
cd backend
uv run pytest
```
