# Team-control request signatures

`awid.team_control_requests` and Go package `awid` own these request preimages
and the controller-claim artifact. They use the common primitives described in
[signature-primitives.md](signature-primitives.md). Neither module reads a
registry, checks a timestamp window, nor authorizes an ownership effect.

## Ordinary import

`TeamImportRequest` retains the released `byoidt_import` preimage. Its canonical
JSON has exactly these six fields:

- `operation`: `byoidt_import`.
- `awid_team_id`: the supplied canonical team, with surrounding whitespace removed.
- `organization_id` and `team_id`: supplied selectors with surrounding whitespace
  removed; an absent selector becomes an empty string in the preimage.
- `dry_run`: an actual boolean.
- `timestamp`: the supplied time with surrounding whitespace removed.

Python stores nullable selectors unchanged; Go's preimage struct uses empty
strings for absent selectors. The transport adapter preserves released null
selectors in the body. This signature covers metadata only: member certificates
and roster facts require their own checks. No additional team or selector grammar
is imposed by the signing owner.

## Fully unowned team claim

`UnownedTeamClaimRequest` signs exactly five fields:

- `operation`: `claim_unowned_team`, fixed by the type.
- `awid_team_id`: the canonical team, with surrounding whitespace removed.
- `email` and `username`: the prospective owner's already-normalized values,
  signed verbatim. The account owner supplies normalization and account policy.
- `timestamp`: the supplied time with surrounding whitespace removed.

This is distinct from the import preimage. A member credential does not authorize
claiming a fully unowned team. The admitting host obtains the team's current
controller fresh from the registry, verifies this claim with that controller,
checks the existing 300-second timestamp window, and matches the exact target
before any account, organisation or registry effect. The created or reused
account must match the signed normalized email. An organisation-owned signup
lane retains its own authority. The member-authenticated HTTP envelope remains
transport authentication; the controller artifact authorizes this claim.

The public artifact has exactly this shape; all leaf values are strings:

```json
{
  "request": {
    "operation": "claim_unowned_team",
    "awid_team_id": "research:acme.com",
    "email": "owner@example.com",
    "username": "owner",
    "timestamp": "2026-05-09T12:00:00Z"
  },
  "signer_did_key": "<did:key derived from the signing key>",
  "signature": "<unpadded standard-base64 Ed25519 signature>"
}
```

The signature covers the canonical `request` object, including `operation`.
The signer field identifies the integrity key; it is never an authority stamp.
The reader rejects unknown or duplicate fields, wrong types or operation,
invalid Unicode, trailing JSON, and serialized artifacts larger than 16 KiB.
Parsing and integrity verification are separate. Hosts must not treat a parsed
artifact or an embedded signer as an admitted controller claim.

## Public APIs and consumers

Python exports frozen, keyword-only `TeamImportRequest`,
`UnownedTeamClaimRequest` and `SignedUnownedTeamClaim`. Request methods are
`signing_bytes()`, `sign(signing_key=...)` and
`verify_signature(signer_did_key=..., signature=...)`. Import signing returns a
signature string; claim signing returns its artifact. A Python signing key is a
32-byte Ed25519 seed.

`read_unowned_team_claim(value)` accepts JSON bytes, JSON text, or an already
parsed object. The returned artifact exposes immutable `request`,
`signer_did_key` and `signature`; `to_dict()` makes a detached transport object,
`to_json()` returns canonical UTF-8 JSON bytes, `verify_integrity()` checks its
embedded signer, and `verify_signature(signer_did_key=...)` additionally requires
that exact independently obtained controller. Shape failures raise
`TeamControlRequestError`; signature failures raise `TeamControlSignatureError`.

Go exports the same three types and `TeamControlSignature{SignerDIDKey,
Signature}`. Request methods are `SigningBytes`, `Sign(ed25519.PrivateKey)` and
`VerifySignature(TeamControlSignature)`. `ParseUnownedTeamClaim([]byte)` owns the
reader. `json.Marshal(artifact)` uses the shared serializer; artifact methods
`VerifyIntegrity()` and `VerifySignature(expectedSignerDIDKey)` mirror Python.
All returned errors include a recovery action.

Consumers keep registry/freshness admission in its existing evidence owner,
file I/O in the CLI carrier owner, and account-policy/effect checks in the host.
The producer is `aw id team claim-human-request`; the transport carrier is
`aw claim-human --controller-claim-file <file>` with optional JSON field
`controller_claim`. These command adapters are coordinated consumer changes;
the shared module alone does not add the commands to a released binary.

## Shared evidence

[team-control-requests-v1.json](vectors/team-control-requests-v1.json) is consumed
by both languages' production codecs and signature methods. Its first import
case matches the released CLI's existing exact signature. The additional cases
cover nullable/blank selectors, whitespace and Unicode serialization, both
boolean values, prospective/existing claim targets and the full artifact.
Target/time tampering, cross-operation signature reuse and malformed artifacts
have refusal tests beside valid round-trip neighbors. No earlier frozen vector
file changes.

The claim binding follows Antares' controller-authority ruling relayed in
`9117ca82-fdad-42eb-acbc-8311994a9e22`, with normalized email/username binding
specified in `9d4835b6-44c3-46e5-a32f-18883f009110`.
