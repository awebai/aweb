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

## Compatibility: deprecated compact v1

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

## Nonce extension and replay protection

This additive extension is staged: verifiers must implement the rules below
before clients emit nonces. A deployed verifier without this extension provides
request binding, not replay protection. The nonce-free aw 1.36.45 release does
not depend on this extension.

A v2 payload may include `nonce`, encoded as exactly 16 random bytes in canonical
unpadded base64url (22 characters). A present value must be a string, decode to
exactly 16 bytes, and equal its unpadded base64url re-encoding; otherwise refuse
with 401. Empty values, padding, alternate alphabets and noncanonical trailing
bits are invalid. Absence remains valid for released clients. Other signed
operation-specific fields remain supported as described above.

Once every verifier accepts this extension, the shared request signer in each
language generates a fresh nonce with its CSPRNG for every outgoing root request,
including SSE reconnects and retries. `nonce` is reserved alongside the existing
authoritative fields: caller custom JSON cannot supply or replace it. There is
no downgrade after a refusal. A new request, even to the same target in the same
second, receives a new nonce and signature.

After signature, timestamp and current identity/certificate authority checks
succeed, the relying service atomically claims a replay key derived from the
signer's `did:key` and the **decoded signature bytes**. Use an unambiguous encoding
of that pair before hashing; different textual base64 representations must not
create distinct replay keys. The key expires at the signed timestamp plus
300 seconds. Because the accepted window is plus or minus 300 seconds, a
future-dated request can require retention for nearly 600 seconds after receipt.
A later authorization or resource error does not make the proof reusable.

For a nonce-bearing request:

- A previously unclaimed key is accepted and recorded exactly once.
- An already claimed key is refused with 401 and distinct code
  `request_replayed`.
- An unavailable replay store returns 503; it never disables enforcement or
  silently switches to a process-local store.

For a nonce-free v2 request, record nonce-free usage and repeated signatures,
labelled by authentication family, method, route template and client version.
Duplicates remain accepted. If the store is unavailable, omit the duplicate
count and preserve existing availability. This compatibility path has no replay
protection. Compact v1 remains accepted and measured separately as above.

Cloud and other multiprocess deployments use a shared Redis store with an atomic
claim and expiry. An explicit in-memory mode is permitted only for a documented
single-process self-hosted service; it cannot protect multiple workers or retain
claims across a restart. A configured Redis failure must never select that mode.
Only hashes and expiry are retained, with no credential or signature logging.

A bridge and downstream dependency authenticating the **same incoming request**
must share its claim result, so one request consumes one replay entry. This
memoization is local to that request; a separate request carrying identical
headers must consult the shared store and receive the replay refusal.

The deployment sequence is server verifier support, then every embedding host
(including Cloud), then naapp-lib verifier support, then nonce-generating Go,
Python and TypeScript clients and the rebuilt channel, Pi and wake artifacts.
Do not require nonce presence during this sequence. Retirement of compact v1
and nonce-free v2 is a separate, explicitly approved operator cutoff based on
the measured usage. This extension does not set or activate that cutoff.

## Onboarding key-possession requests

Onboarding HTTP DIDKey proofs use the identity-only v2 envelope above, with
`did_aw` equal to the claimed stable identity or empty when only a key is being
proved. This envelope proves key possession only: existing route-specific
checks still authorize creation, joining, reuse or recovery. A new key proof
cannot create team membership or controller authority by itself.

Normal DIDKey authentication carries the standard headers above. When another
credential occupies `Authorization`, the proof uses
`X-AWEB-DIDKey-Signature`, `X-AWEB-DIDKey-Timestamp` and the new
`X-AWEB-DIDKey-Signed-Payload`; that last header carries the same canonical v2
payload bytes. The verifier compares the stable identity claim with the route's
expected claim and applies current-key resolution where that route requires it.
The external audience, raw target/query and exact body remain bound.

Verifiers add v2 acceptance and old-form usage counting before onboarding
clients switch to the shared signer. The historical method/path/body/timestamp
proof remains accepted and counted until its separately approved cutoff; it
lacks audience binding. A malformed presented v2 proof never falls back to that
old form. Nonce validation and replay behavior are the same as above. Registry
controller operations and DID-log artifacts keep their distinct purposes and
are governed by the registry contract; they are not team-member requests.

## Conformance vectors

[`vectors/team-auth-envelope-v2.json`](vectors/team-auth-envelope-v2.json)
contains deterministic Ed25519 cases for both a neutral OSS task request and a
hosted-route interoperability example, including a positive request without
`operation`, plus cross-endpoint, cross-origin,
tampered-body, and missing-version negatives. Consumers must verify every
current positive case rather than treating the first array entry as the corpus.
