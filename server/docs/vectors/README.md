# Protocol conformance vectors

This directory publishes **deterministic conformance vectors** for the OSS
`aweb` identity, continuity, and verification rules defined in:

- [id-sot.md](../id-sot.md)
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
  - Canonical stable-identity audit-log entry payload
  - Expected `entry_hash` (sha256 hex)
  - Expected Ed25519 signature (base64, **no padding**)

- `stable-id-v1.json`
  - `did:key` → stable ID derivation vectors

- `rotation-announcements-v1.json`
  - Canonical rotation-announcement payloads (single link + chaining)
  - Expected Ed25519 signatures (base64, **no padding**)

## Encoding notes

- **Canonical JSON:** lexicographic key sort, compact separators, literal UTF-8 (no `\uXXXX` escapes).
- **Signatures:** Ed25519 signature bytes encoded as base64 (RFC 4648), no `=` padding.

## Validation

The backend test suite validates these vectors:

```bash
cd backend
uv run pytest
```
