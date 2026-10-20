# AWID controller request binding

Namespace and team controllers retain their existing authority. Controller
possession does not establish identity custody or permit a member to register or
revoke certificates. This additive HTTP envelope covers every written field in
header-authenticated namespace, team and address mutations.

## Covering wire

`Authorization: DIDKey <controller did:key> <signature>` signs canonical UTF-8
JSON bytes carried in base64url `X-AWEB-Signed-Payload`. Required fields are the
existing operation-specific claims (`domain`, `operation`, and the route's name,
team name, certificate ID or preconditions) and:

```json
{
  "v": 2,
  "type": "aweb.awid-controller-request",
  "aud": "https://registry.example.com",
  "method": "POST",
  "path": "/v1/namespaces/example.com/teams",
  "body_sha256": "<SHA-256 of exact HTTP request body bytes>",
  "timestamp": "<X-AWEB-Timestamp>"
}
```

Every field is required, canonical bytes must match exactly, and extra claims
are refused. `method` is uppercase; `path` is the external raw path plus raw
query, including a mount prefix and percent-encoding. Timestamp skew remains
300 seconds. A covering header, including an empty or malformed one, never
falls back to a legacy signature. Controller requests cannot use the team-auth
v2 purpose, and team-auth refuses the AWID purpose.

`aud` must be a canonical origin from `AWID_PUBLIC_ORIGINS` (comma-separated), or
an embedding's explicit `app.state.awid_public_origins`. It is never derived
from Host or forwarded headers. A covering request fails closed with 503 when
no origins are configured. Configure each registry's public origins before
migrating its clients. Legacy request verification is unaffected by this setting.

Parent authorization has its own `X-AWEB-Parent-Authorization`,
`X-AWEB-Parent-Timestamp`, and `X-AWEB-Parent-Signed-Payload`. It binds the same
HTTP request body, method and path, with its parent authorization operation.
Existing atomic-claim and DID-log proofs are separately versioned signed body
artifacts; they retain their existing canonical bytes and authority checks.

## Certificate records

Every new certificate registration, under either HTTP envelope, requires the
complete team-signed certificate blob. ID, team, team key, member key, optional
stable DID and address, alias and scope must match the verified blob. Missing or
mismatched blobs are refused; historical blob-free records remain readable and
retain the existing explicit reissue-required response when fetching the blob.
The certificate's optional stable DID remains controller-asserted; this change
does not add an independent stable-identity verification claim.

## Rollout and measurement

Deploy the accepting AWID server and configure its origins first. Then publish
and deploy the Python RegistryClient and aw clients that sign covering requests.
Clients must not silently retry a covering refusal using a legacy signature.
Old forms remain accepted until Juan chooses their cutoff from measured use.
Their unsigned-field weaknesses are not repaired by merely deploying an accepting
server; migration and the later cutoff complete that protection.

Successful legacy operations increment `app.state.legacy_controller_auth_counts`
once per request and operation, including a distinct parent operation where
used. Structured `awid_legacy_controller_auth_accepted` metrics report each
operation's cumulative count at one and powers of two, following AWID's existing
service-exemption metric convention. Invalid proofs, refused operations and
covering requests do not increment it. Only a closed operation name and count
are emitted: no domains, caller identifiers, bodies or credentials. There is no
public metrics endpoint or new telemetry SDK.

The published aw 1.36.43 always sends the blob. Cloud's production registration
wrapper also supplies a minted or validated persisted blob on every call;
its paired change refuses an empty blob before calling the registry. Historical
test evidence is seeded as old data, rather than creating a new unsigned record.

## Client APIs and external signing

The Python `awid.registry.RegistryClient` and Go `awid.RegistryClient` sign
controller mutations after JSON serialization, over the exact transmitted body.
The audience is the canonical origin of the configured or discovered registry
URL. Mutation redirects are errors; neither client follows them or downgrades
to legacy authentication after refusal. Self-hosted registries must run AWID
**0.5.29 or later**, with their public origins configured, before clients upgrade.
Certificate registration refuses a missing team-signed blob before sending.

Python exposes `delete_team` and `delete_namespace` for lifecycle cleanup, plus
`controller_request(method, path, claims=..., body=..., registry_url=...)` for
controller operations such as rotation and signed-record publication. It accepts
either `signing_key` or the pair `controller_did_key` and async `signer`.
Parent authorization uses `parent_claims`, `parent_controller_did_key` and
`parent_signer`, separately from the child's operation.

`awid.controller_signing.ControllerSigningRequest` is frozen and contains
`controller_did_key`, `operation`, and `canonical_payload`. The SDK serializes
first, invokes the signer, verifies its returned base64 Ed25519 signature against
the named key, and sends only after verification. Callbacks may perform network
I/O; invoke them outside database transactions. Payloads and keys are not logs.

A signing service must use the public pure `parse_controller_request(bytes)`
and `build_controller_payload(ControllerRequest)` functions. The frozen typed
request contains `v`, `type`, `operation`, `aud`, `method`, `path`, `body_sha256`,
`timestamp`, and immutable `route_claims`. The parser refuses unknown or missing
fields, a different protocol/version, and noncanonical bytes. The signing service
checks its allowed audiences, the key's operation policy, namespace/team binding,
and timestamp freshness, then rebuilds and signs SDK-derived bytes. When supplied
bytes, it requires the rebuilt bytes to equal them. The outer signing operation
must equal the parsed operation. It never signs arbitrary caller bytes. Log only
operation, domain and outcome, never payloads or key material.

Go exports `SignAWIDControllerRequest(key, method, requestURL, body, claims,
timestamp)` for exact serialized bytes and `RegistryClient.ControllerRequest`
for sending JSON mutations. `ParentControllerHeaders` maps an independently
signed parent proof to its distinct headers. Existing signed record, atomic
claim and DID-log protocols keep their own canonical bytes.

Legacy acceptance is retained and measured. Publishing these clients does not
itself retire the old envelope: Juan sets that cutoff from per-operation usage,
and removal is a separate server change.
