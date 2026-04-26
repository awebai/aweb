# Trust Conformance Vectors

These vectors define shared trust-verification contract cases that must pass in
both the Go CLI verifier and the channel TypeScript verifier.

The first vector file covers recipient binding only. Later files should extend
the same pattern for crypto signature handling, sender registry verification,
and TOFU pin continuity.

Recipient-binding vectors start after crypto verification and assert that a
verified message is bound to the local receiver by stable `did:aw` first, with
current `did:key` fallback. Non-verified statuses must pass through unchanged.

## `recipient-binding-v1.json`

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
