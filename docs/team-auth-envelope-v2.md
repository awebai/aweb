# Team-Auth Request Envelope v2

Status: **canonical current relying-party protocol**. Team-auth proves that a
member identity holding a valid team certificate authorized one concrete HTTP
request. AWID supplies team public-key and revocation authority; the relying
service verifies the envelope and applies its own authorization policy.

## Headers

```
Authorization: DIDKey <member did:key> <base64-signature>
X-AWEB-Timestamp: <RFC 3339 UTC timestamp>
X-AWEB-Signed-Payload: <base64url canonical JSON>
X-AWID-Team-Certificate: <base64-encoded certificate JSON>
```

## Signed Payload

The `X-AWEB-Signed-Payload` bytes are canonical JSON with sorted keys and no
extra whitespace. Version 2 requires these fields:

```json
{
  "aud": "https://coordination.example.com",
  "body_sha256": "<hex sha256 of request body bytes>",
  "method": "POST",
  "path": "/v1/tasks",
  "team_id": "engineering:example.com",
  "timestamp": "2026-06-12T10:00:00Z",
  "v": 2
}
```

`operation` is optional, informational metadata. The auth layer neither
requires it nor verifies its value against the requested operation; the signed
`method` and raw `path`/query bind the request target. Operation-specific fields
may be present and are ignored by the auth layer. If present, these fields are
still covered by the signature over the complete canonical payload.

## Verification

The verifier:

1. Parses `Authorization` and extracts the signing `did:key` and signature.
2. Parses `X-AWEB-Timestamp` and enforces a timestamp skew window of at most
   five minutes.
3. Decodes `X-AWEB-Signed-Payload` as base64url bytes.
4. Verifies the Ed25519 signature over those exact presented bytes.
5. Parses the payload and requires it to be canonical JSON.
6. Requires `v == 2`.
7. Binds the signed claims to the actual request:
   - `aud` must be one of the server's configured public origins.
   - `method` must equal the HTTP method in uppercase.
   - `path` must equal the external raw percent-encoded path plus raw query.
     Mounted deployments include `root_path`, so an app mounted at `/api`
     verifies `/api/v1/...`, not only the inner `/v1/...` route.
   - `body_sha256` must equal the middleware-computed body hash.
   - `team_id` must equal the team id in the presented team certificate.
   - `timestamp` must equal the timestamp header.
8. Verifies the team certificate against AWID team authority and revocation
   state, and requires `certificate.member_did_key == signing did:key`.

Independent applications without an operator token can obtain the current
team key and revocation status from AWID's anonymous
`/v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/status`, even
for private teams. This path requires a published certificate and refuses an
unknown record. Cache per team and certificate for at most 60 seconds and fail
closed on refresh failure. Active status never replaces certificate signature
verification against the current team key; rotation invalidates old-key
signatures. Existing token/history, server and CLI verification is unchanged.
See [the registry contract](awid-sot.md#teams).

The verifier must not trust request headers such as `Host` or
`X-Forwarded-Host` for `aud`. Public origins are configuration, not caller
input.

## Compatibility: compact v1

Version 2 above is the current protocol for new clients. When
`X-AWEB-Signed-Payload` is absent, current aweb verifiers retain a bounded
compatibility path for the legacy compact payload:

```json
{
  "body_sha256": "<hex sha256 of request body bytes>",
  "team_id": "default:aweb.ai",
  "timestamp": "2026-06-12T10:00:00Z"
}
```

This v1 shape does not bind method, path, or audience and must not be used for
new relying-party clients. Accepting it is compatibility behavior, not evidence
that v1 and v2 provide equivalent security.

## Identity-only requests

Identity-only authentication uses the same v2 canonicalization and target binding,
with the required `did_aw` claim in place of `team_id`. Its value equals
`X-AWEB-DID-AW`, or the empty string for a local identity. The verifier still
resolves a nonempty `did_aw` against AWID's current key. This proves possession
of that identity, not team membership; certificate, grant and route authority
checks remain separate. Missing `did_aw` is invalid, including for local identities.

Identity-only compact v1 (`body_sha256`, `did_aw`, `timestamp`) remains accepted
alongside the certificate compact v1 above. Deploy server support, update and
deploy every embedding host's verifier, then publish clients that emit v2.
Clients must not fall back to v1 after v2 refusal.

## Legacy usage metric

`aweb.auth_metrics.LEGACY_REQUEST_AUTH_ACCEPTED` exports the Prometheus counter
`aweb_legacy_request_auth_accepted_total`. It counts requests after successful
compact-v1 authentication, once per request, labelled by `auth_family`
(`certificate` or `identity`), HTTP `method`, matched `route` template and
`client_version`. Authenticated requests that subsequently fail route authorization
or resource lookup still count; refused authentication and v2 requests do not.
The CLI version comes from `User-Agent: aw/<version>`; absent or unrecognized
versions use `unknown`. No signatures, credential headers, raw paths, query strings,
or member identifiers are recorded. Embedding hosts expose the Prometheus registry
through their own instrumentation; the OSS app installs no public metrics endpoint.
The metric provides evidence for a later separately approved v1 cutoff, and
never changes request acceptance.

## Replay

Version 2 is request-bound but not replay-proof. A byte-identical request can
be replayed inside the accepted timestamp skew window if an attacker can capture
the signed request. Product copy and protocol docs must not claim replay
protection.

A future nonce-bearing protocol revision must define nonce scope and lifetime,
use a shared deduplication store, and specify fail-closed behavior when that
store is unavailable. Until clients and relying services implement that complete
contract, the timestamp window above is the replay limit.

## Conformance vectors

[`vectors/team-auth-envelope-v2.json`](vectors/team-auth-envelope-v2.json)
contains deterministic Ed25519 cases for both a neutral OSS task request and a
hosted-route interoperability example, including a positive request without
`operation`, plus cross-endpoint, cross-origin,
tampered-body, and missing-version negatives. Consumers must verify every
current positive case rather than treating the first array entry as the corpus.
