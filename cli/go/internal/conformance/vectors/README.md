# Conformance vectors

These vectors define byte-level contracts shared by independent aweb consumers.

Existing AWID/trust vectors cover signing, stable IDs, rotation announcements,
and team-auth envelopes.

## `app-manifest-interpretation-v1.json`

Manifest interpretation vectors are the anti-drift contract for app manifests.
They assert the interpreted request spec **before signing**:

`manifest + verb + args -> method, absolute URL, raw path+query, headers, body bytes, body_sha256, mutation`

They intentionally do **not** assert dynamic `Authorization`, timestamp, or
signature bytes; those stay in the team-auth crypto vectors.

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
- security rejection cases: scheme/host paths, `..` traversal, unsupported
  methods, reserved names/aliases, float body fields for v1, and external
  plugin PATH rejection as a shared invariant

Future consumers, including the hosted gateway, should run the same vector file
and compare byte-identical interpreted specs.
