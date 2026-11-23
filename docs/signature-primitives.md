# Signature and request primitives

Status: current shared primitive contract. Typed artifacts select fields and
establish authority; primitive success proves possession of the selected key,
not custody, membership, namespace control or permission to perform an act.

## Owners and verification profiles

Go uses `signaturewire`, Python uses `awid.signature_wire`, and TypeScript uses
`identity/signature_wire`. Each has one raw signer and one verifier. Public
artifact helpers remain adapters to these owners.

Every admitted public key is canonical, nonidentity and in the Ed25519 prime
subgroup. Verification uses exact presented bytes, a 64-byte signature, canonical
scalar S below the group order, and the noncofactored Ed25519 equation. Small-order
R is refused, including identity R. ID certificates additionally require R in
the prime subgroup. The stricter ID profile is not substituted for another
artifact's field, lifetime or authority rules.

The canonical, nonidentity, prime-subgroup public-key requirement is a deliberate
policy enforced by the shared verifier in every family and all three runtimes,
including Go and Python. This is an explicit acceptance rule, not merely a move
of existing calls. The shared vector's `ed25519-small-order-A-0` through `-7`,
`ed25519-noncanonical-A-identity`, `ed25519-noncanonical-A-x0-sign-bit`, and both
`ed25519-mixed-order-A-*` cases require refusal in all three; the honest control
requires acceptance.

All three message verifiers refuse mixed-order R. The shared
`ed25519-mixed-order-R-honest-A` case has a prime-subgroup public key and a
mixed-order R; its expected result is `failed` for Go, Python and TypeScript.
It exercises the message verifier even though its opaque signed bytes come from
an ID-certificate fixture. Go and Python's native verification reject it;
TypeScript applies the noncofactored equation explicitly. Ordinary Ed25519
signing computes R as a scalar multiple of the prime-order base point, so
released standard signers cannot emit a mixed-order R
([RFC 8032 section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.6)).

The message-family changes are deliberate: TypeScript refuses mixed-order R
under ruling `2c74f907-fee7-496f-bba7-1dadbaefee37`; Go refuses identity/small-order
R under ruling `beb23450-5400-473e-9651-0e25bfb649f9`. The public
`signature-primitives-v1.json` vector records these decisions and their ordinary
valid neighbors. No existing ID-certificate vector is re-frozen.

## Encoding compatibility

Typed families select named codec profiles. Go and TypeScript message signatures
use unpadded standard base64, retaining CR/LF acceptance. Python retains its
released lenient signature spellings in this release. After successful signature
verification, each noncanonical spelling increments the process counter and logs
`event=awid_noncanonical_signature_accepted value=N`, without signature material.
An atomic-claim identity proof is hashed over exactly the bytes this verification
decoder accepts, so equivalent accepted spellings cannot change its digest.

Go retains case-insensitive signed-metadata interpretation. A cryptographically
verified payload with a known metadata key spelled with different case increments
`aw_noncanonical_signed_metadata_verified` with its process counter `value`.
Neither invalid signatures nor ordinary exact-name claims increment it. These
measurements do not add refusals; any later narrowing is a separate decision.

Canonical JSON has one owner per language, with explicit profiles for released
wire objects, safe-integer objects and local digests that escape line separators.
Typed builders own field presence and null/omission choices. `canonical-json-v1`
and the existing artifact vectors retain their bytes. The standalone Secrets
runner retains its dependency boundary and runs the common Unicode and URL-codec
vectors against its own installation. Its `signature_wire` module checks
canonical nonidentity prime-subgroup points for A and R and the scalar bound
before calling its existing cryptography backend. It runs the shared point
and signature vectors too.

## Shared Python producers

`awid.team_certificate.issue_team_certificate` accepts keyword-only team ID,
held team signing seed, member key, alias and scope. It returns the signed public
certificate and its base64 JSON blob. Legacy `lifetime` inputs use the shared
scope normalizer; emitted certificates use `identity_scope`. Explicit
`certificate_id` and `issued_at` are preserved for retained-operation replay.
The team public key is derived from the held key, never supplied by the artifact.
The caller establishes issuance authority; this helper performs no registry write.

Certificate verification exposes `CheckedTeamCertificate`: immutable claims, the
verified current team key, canonical bytes of the complete decoded artifact
including its signature, and a lowercase SHA256 hex fingerprint.
`verify_team_certificate_claims` checks shape, subject and crypto once;
`check_team_certificate_evidence` applies revocation and registration to that
snapshot. The existing `check_team_certificate` adapter retains its return and
refusal ordering. The effect owner can examine an already checked artifact for a
revocation-only retained continuation without parsing or verifying it again.

`awid.request_auth.team_auth_request_headers` produces relying-party v2 headers
from an explicit configured audience, actual uppercase method, external raw path
and query, exact body bytes, team and timestamp. It returns Authorization,
X-AWEB-Timestamp and X-AWEB-Signed-Payload. The audience never comes from Host.
Certificate presentation remains the caller's job; the producer does not retry a
refusal with compact v1. Existing compact, controller, onboarding and path-read
formats remain accepted by their existing typed consumers.

## Local private keys

Go's private PEM writer and codec live in `awid/keys.go`; Ed25519 team,
namespace, identity and session keys share them. X25519 uses the same private
PEM writer. Writes are atomic, files are 0600 and newly created private parent
directories are 0700. Exclusive creation preserves an existing occupant.
Python consumers of the CLI Ed25519 PEM use
`awid.signing.load_signing_key_pem`. Callers still own path and permission checks.

On POSIX platforms, readers retain mounted-secret compatibility. Windows access
continues to follow profile ACLs rather than POSIX mode diagnostics.
Group- or other-readable keys remain
usable and produce one warning per file per command with the exact `chmod 600`
command. `aw doctor` reports the selected signing key's permissions and offers a
safe fix that changes mode without changing key bytes. Other private key files
inside named roots are reported and can be fixed through the same command.
Directory diagnosis is limited to the workspace `.aw`, the explicitly selected
identity home, and `~/.awid` with its `controllers` and `team-keys` directories.
Only an explicit doctor fix changes those directory modes; key reads and writes
leave existing parent directories alone. Permission-based refusal
is deferred by the operator's ruling relayed in
`90ff2d44-fcf8-40a7-ad60-d779b8b38a25` and clarified in
`f865acca-9b36-4f18-9bc4-11b902db3553`.

The doctor safety gate evaluates the registered repair owner's typed operation,
selected path and permission mode. Metadata repairs are limited to their named
local field and target. A plan's description never grants or removes permission;
key-content writes, replacement/deletion, identity lifecycle and coordination
cleanup remain outside these safe local repairs. Serialized output explains a
plan; it is not an execution capability or a persisted-plan interface.


## Canonical point representation evidence

`signature-point-encoding-v2.json` isolates compressed-coordinate representation,
per [RFC 8032 sections 5.1.2–5.1.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3).
The production predicate in each language checks the 32-byte length, field bound
and zero-x sign rule for both A and R. Curve membership, nonidentity, subgroup
and signature-equation checks remain separate. The shared cases call these
predicates directly and are labelled component evidence; canonical identity and
torsion encodings are valid representation controls, not admissible signers.

Antares accepted this evidence in `0a7453e1` (relayed in
`7be295e4-3463-473a-8dd5-f9eb522aa145`). A noncanonical encoding is available only
for the few y values at or above the field prime. Constructing a full valid
signature for those points would require an unknown discrete logarithm; the
corpus therefore makes no claim that its full-signature negatives isolate the
encoding rule. The frozen v1 signature and ID corpora stay unchanged.

Author mutation checks inverted the production A or R gate in Go and Python,
and their common point gate in TypeScript. In each case the existing
`raw-standard` positive full-signature case failed: Go
`TestPublicSignaturePrimitiveVectors/raw-standard`, Python
`test_all_public_message_verification_cases`, and TypeScript `raw-standard`.
Restoring the source passes the same tests and the shared component cases.
