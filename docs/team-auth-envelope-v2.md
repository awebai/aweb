# Team-auth request envelope v2

Status: **current public interoperability contract**. Owner: the aweb/AWID
team-certificate request verifier. Source authority lives in
`server/src/aweb/team_auth_envelope.py`, `server/src/aweb/team_auth_deps.py`, and
the `aw id request --team-auth` producer. Exact cross-language bytes and
negative cases live in `docs/vectors/team-auth-envelope-v2.json`; server, Go
conformance, and public naapp verifier tests consume that fixture.

Team-auth requests prove that a member identity holding a team certificate
authorized one concrete HTTP request. This is an optional relying-party
extension contract, not the default mail/chat authentication explanation.

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
  "aud": "https://service.example",
  "body_sha256": "<hex sha256 of request body bytes>",
  "method": "POST",
  "path": "/v1/documents?dry_run=true",
  "team_id": "default:example.com",
  "timestamp": "2026-06-12T10:00:00Z",
  "v": 2
}
```

Operation-specific fields may be present and are ignored by the auth layer.

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

The verifier must not trust request headers such as `Host` or
`X-Forwarded-Host` for `aud`. Public origins are configuration, not caller
input.

## Legacy v1

When `X-AWEB-Signed-Payload` is absent, servers may accept the legacy compact
payload during migration:

```json
{
  "body_sha256": "<hex sha256 of request body bytes>",
  "team_id": "default:aweb.ai",
  "timestamp": "2026-06-12T10:00:00Z"
}
```

This v1 shape does not bind method, path, or audience and must not be used for
new relying-party clients.

## Replay

Version 2 is request-bound but not replay-proof. A byte-identical request can
be replayed inside the accepted timestamp skew window if an attacker can capture
the signed request. Product copy and protocol docs must not claim replay
protection.

Nonce-based replay protection does not ship. Adding it requires a versioned
contract amendment, a shared deduplication store, retention/cleanup rules, and
an explicit fail-open versus fail-closed availability decision.
