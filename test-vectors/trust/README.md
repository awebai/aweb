# Trust Conformance Vectors

These vectors define shared trust-verification contract cases that must pass in
both the Go CLI verifier and the channel TypeScript verifier.

The first vector files cover crypto signatures, sender registry verification,
and recipient binding. Later files should extend the same pattern for TOFU pin
continuity.

## `crypto-sig-v1.json`

Crypto signature vectors cover Pass A. They assert signature verification over
the server-supplied canonical `signed_payload` bytes, before recipient binding,
sender registry checks, or TOFU pinning.

Top-level fields:

- `schema`: must be `aweb.trust.crypto-sig.v1`.
- `description`: human-readable summary.
- `vectors`: ordered list of crypto-signature cases.

Vector fields:

- `name`: stable test case identifier.
- `signed_payload`: canonical JSON string that was signed.
- `signature`: base64 Ed25519 signature over `signed_payload`.
- `from_did`: claimed sender `did:key`.
- `signing_key_id`: optional equality guard. `null` means omitted, `""` means
  present but empty; both are treated as absent.
- `expected_status`: canonical status after crypto-signature verification.

`signing_key_id` does not select an alternate public key. A non-empty value
must equal `from_did`; otherwise the status is `failed`. Verification uses the
public key extracted from `from_did`.

## `registry-v1.json`

Sender registry vectors cover Pass C. They start after crypto has already
produced an upstream status and before local TOFU pinning. The registry can
confirm that the sender's stable `did:aw` currently maps to the presented
`did:key`, reject a hard mismatch, or degrade without changing the upstream
status.

Top-level fields:

- `schema`: must be `aweb.trust.registry.v1`.
- `description`: human-readable summary.
- `vectors`: ordered list of sender registry cases.

Vector fields:

- `name`: stable test case identifier.
- `initial_status`: input status from the upstream crypto pass.
- `trust_address`: canonical sender address passed to the registry resolver.
- `from_did`: sender `did:key` from the verified envelope.
- `from_stable_id`: sender stable `did:aw` from the verified envelope or server metadata.
- `registry_state`: stub resolver map keyed by `from_stable_id`; each entry has:
  - `outcome`: `verified`, `hard_error`, or `ok_degraded`.
  - `current_did_key`: registry current key for `verified` results, or empty.
- `expected_status`: canonical status after sender registry verification.
- `expected_confirmed_current_key`: whether the registry proved that the
  current key exactly matches `from_did`, for downstream pin disambiguation.

## `recipient-binding-v1.json`

Recipient-binding vectors start after crypto verification and assert that a
verified message is bound to the local receiver by stable `did:aw` first, with
current `did:key` fallback. Non-verified statuses must pass through unchanged.

Top-level fields:

- `schema`: must be `aweb.trust.recipient-binding.v1`.
- `description`: human-readable summary.
- `vectors`: ordered list of recipient-binding cases.

Vector fields:

- `name`: stable test case identifier.
- `initial_status`: input status from the crypto pass.
- `self_did`: verifier's current `did:key`.
- `self_stable_id`: verifier's stable `did:aw`.
- `to_did`: message recipient binding from the signed envelope or server metadata.
- `to_stable_id`: message stable recipient binding from the signed envelope or server metadata.
- `expected_status`: canonical status after recipient-binding normalization.

Stable `did:aw` recipient comparisons are case-insensitive to match Go's
`strings.EqualFold`; current `did:key` fallback comparisons remain
case-sensitive.
