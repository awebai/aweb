# Conformance vectors

These vectors define byte-level contracts shared by independent aweb consumers.

Existing AWID/trust vectors cover signing, stable IDs, rotation announcements,
and team-auth envelopes.

## `app-emit-credential-v1.json`

The vector's `aud` (`core.aweb.ai`) and `path` (`/v1/events/app`) are
byte-parity fixture values for the signing algorithm, not mandated runtime
endpoints. At runtime, the signer uses the actual external audience as a bare
origin (for example, `https://app.aweb.ai`) and the root-path-aware
`raw_request_target` that the verifier reconstructs.

For app-emit credentials, standalone deployments sign `/v1/events/app`. Hosted
deployments mounted at `root_path=/api` sign `/api/v1/events/app` because the
mount prefix is part of the reconstructed raw request target. Query strings, if
present, are included exactly as reconstructed in `raw_request_target`.

The vector freezes the canonical JSON, `body_sha256`, and signature
construction. `aud` and `path` are runtime request bindings.

## `app-manifest-interpretation-v1.json`

Manifest interpretation vectors are the anti-drift contract for app manifests.
They assert the interpreted request spec and deterministic signed-payload input
**before dynamic signing**:

`manifest + verb + args -> method, absolute URL, raw path+query, headers, body bytes, body_sha256, mutation, canonical team-auth payload bytes`

They intentionally do **not** assert dynamic `Authorization` or signature bytes;
those stay in the team-auth crypto vectors.

Coverage includes:

- explicit param placement (`path`, `query`, `body`)
- origin + relative-path target construction
- RFC3986 path-param percent-encoding
- canonical query encoding in params declaration order, arrays as repeated keys
- optional fields omitted, not empty
- body type coercion before canonical JSON serialization
- explicit `Content-Type` for JSON and raw bodies
- raw body bytes via body-file/stdin-equivalent input
- mutation classification
- security rejection cases kept beside positives in this file: scheme/host
  paths, `..` traversal, unsupported methods, reserved names/aliases, malformed
  raw body declarations, and float body fields for v1

External-plugin PATH rejection is a CLI dispatch invariant and lives in
`cmd/aw/plugin_test.go`, not in the shared app-manifest interpretation vectors.

Future consumers, including the hosted gateway, should run the same vector file
and compare byte-identical interpreted specs.

## Repository-level app manifest fixtures

Digest-pinned raw manifest snapshots live under
`test-vectors/app-manifests/` at the monorepo root. The Go conformance suite
loads `app-manifest-fixtures-v1.json`, verifies each raw
`/.well-known/aweb-app.json` byte snapshot against its pinned SHA-256 before
parsing, then runs offline interpretation cases against the parsed manifest.
These fixtures are self-contained and must not reach into another repository.
