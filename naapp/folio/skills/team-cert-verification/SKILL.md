---
name: team-cert-verification
description: Use when implementing or reviewing AWID team-certificate authentication — verifying the request-bound v2 team-auth envelope, adopting the shared naapp runtime, building a BYOT relying party, wiring aw id request --team-auth, or debugging X-AWEB-Signed-Payload and team certificate failures in a new service.
---

# Team certificate verification

Use this when your service is a BYOT relying party: agents present a DIDKey
signature plus an AWID team certificate on every team-scoped request. The code
ground truth is `naapp-lib/src/aweb_naapp/runtime/team_auth.py`; the test ground truth is
`naapp-lib/tests/runtime/test_team_auth_envelope.py`, together with
`naapp-lib/tests/runtime/test_team_auth_vectors.py` and
`naapp-lib/tests/runtime/test_awid_team_cache.py`. These paths are relative to
the aweb repository root. Reuse `NaappRuntime.principal` from
`naapp-lib/src/aweb_naapp/runtime/app.py` rather than copying a verifier into
each app.

## Envelope contract

Every team-scoped request carries four headers:

```http
Authorization: DIDKey <did:key:z6Mk...> <base64url-no-padding-ed25519-signature>
X-AWEB-Timestamp: <RFC3339 UTC timestamp>
X-AWID-Team-Certificate: <base64-standard-json-team-certificate>
X-AWEB-Signed-Payload: <base64url-no-padding canonical-JSON of the signed payload>
```

`X-AWEB-Signed-Payload` decodes to canonical JSON with these fields:

```json
{"aud":"https://<service-origin>","body_sha256":"<sha256 hex of request body>","method":"<UPPER>","path":"<raw path?query>","team_id":"<team>:<namespace>","timestamp":"<RFC3339 UTC timestamp>","v":2}
```

Rules:

- The signed-payload header is base64url with no padding (`=` is rejected in
  folio; see `naapp-lib/src/aweb_naapp/runtime/team_auth.py`).
- Parsed JSON must round-trip to the same canonical bytes:
  `canonical_json_bytes(parsed) == decoded bytes` (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`).
- The Ed25519 signature verifies over those decoded presented bytes, not over a
  payload the server reconstructs (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`).

## Ten verification steps

These steps describe the shared verifier; use them when reviewing its integration. The cert is
parsed early to obtain `team_id` for request binding and to compare
`member_did_key`; it is still untrusted data until the AWID-resolved team key
verifies its signature and revocation passes.

1. **Parse DIDKey auth and timestamp** — 401 on bad Authorization,
   missing/invalid timestamp, or timestamp outside skew. Why: this selects the
   request signing key and bounds stale requests.
2. **Decode the team certificate and required fields** — 401 on missing or
   malformed certificate, missing `team_id`/`certificate_id`/`member_did_key`/
   `alias`, or `certificate.member_did_key != request did:key`. Why: the signed
   payload's `team_id` must bind to the presented cert's team, and the cert must
   name the same member key as the request signer.
3. **Read and hash exact request bytes** — store the body bytes and SHA-256.
   Later return 401 if signed `body_sha256` differs. Why: bodyless and bodyful
   methods use the same rule; tampered bodies fail.
4. **Require and decode `X-AWEB-Signed-Payload`** — 401 on missing, malformed,
   padded, non-canonical, or non-object payload. Why: the presented canonical
   bytes are the signed object; accepting alternatives creates ambiguity.
5. **Require `v == 2`** — 401 on absent or other versions. Why: v1/compact
   payloads do not bind method/path/audience.
6. **Bind timestamp, body hash, method, raw path, team id, and audience** — 401
   on mismatch or invalid/disallowed audience. Why: this is what makes a
   captured signature useless against another endpoint, method, team, body, or
   host.
7. **Verify the DIDKey signature over decoded signed-payload bytes** — 401 on
   bad signature. Why: the agent must have signed exactly the payload bytes it
   presented.
8. **Resolve AWID team facts** — 401 for an invalid/unknown team id; 503 for
   unavailable or malformed AWID team-key/revocation facts with no unexpired
   cache entry. Why: AWID, not the cert, is authority for the team key.
9. **Check revocation and verify the certificate signature** — 401 if the
   `certificate_id` is revoked or the cert signature fails; 503 if the
   AWID-resolved team public key is invalid. Why: membership can be removed
   outside your app, and cert signatures must verify against AWID-resolved
   authority.
10. **Build the principal from the verified certificate** — no request-body team
    id. Why: all app queries must scope by the certificate's `team_id`.

## Subtleties that bite

- **Path is raw target, not router path.** Use ASGI `raw_path` plus raw
  `query_string`, preserving percent-encoding and query order; include
  `root_path` for mounted apps. See `naapp-lib/src/aweb_naapp/runtime/team_auth.py` and
  `naapp-lib/tests/runtime/test_team_auth_envelope.py`.
- **Audience canonicalization must match aweb.** Use the same origin rules as
  `aweb.team_auth_envelope` / `awid.log.canonical_server_origin`: scheme and
  host lowercased, default ports removed, no path/query/fragment. See
  `naapp-lib/src/aweb_naapp/runtime/team_auth.py` and the interop check in
  `naapp-lib/tests/runtime/test_team_auth_envelope.py`.
- **Signature verification uses presented bytes.** Decode
  `X-AWEB-Signed-Payload`, verify those bytes, then compare parsed claims to the
  actual request. Do not sign or verify a server-reconstructed dictionary.

## AWID facts and caching

- `AWIDTeamCache` in `naapp-lib/src/aweb_naapp/runtime/team_auth.py` caches
  successful AWID facts in memory for at most 60 seconds. Folio's
  `FOLIO_AUTH_CACHE_TTL_SECONDS` defaults to 60 and accepts 1..60 seconds.
- Without a service token, certificate status is cached per `(team_id,
  certificate_id)`. An unknown certificate is 401; unavailable or malformed
  status, including HTTP 429, is 503. See
  `naapp-lib/tests/runtime/test_awid_team_cache.py`.
- With a service token, team public keys and published/revoked certificate ids
  are cached per team. An unpublished or revoked certificate is refused.
- Use an unexpired entry; after expiry refresh or fail closed. Failed refreshes
  never extend the cache lifetime or make the presented certificate authoritative.
- Misconfigured `public_origin` should make every v2 request fail closed. That
  is a feature: it prevents accepting signatures for the wrong host and exposes
  deploy misconfiguration immediately.

## Anti-patterns

| Anti-pattern | Failure it creates |
| --- | --- |
| Verify the cert against its own `team_did_key` field. | Lets a forged cert bring its own authority. Resolve the team key from AWID. |
| Accept absent version, v1, or compact payloads. | Drops method/path/audience binding and enables cross-endpoint replay. |
| Skip `body_sha256` for GET or empty bodies. | Creates a second contract and lets body mutation bugs hide. Hash exact bytes always. |
| Trust the presented cert when AWID is down. | Converts an availability incident into an auth bypass. Use unexpired cache or fail closed. |
| Set clock skew very wide. | Expands replay window. Keep the default small (folio default: 300 seconds). |
| Add API keys, trusted headers, sessions, or OAuth “just for testing.” | Creates a second auth path reviewers and users must reason about. Test the real verifier. |
| Use router-normalized paths. | Breaks percent-encoding/query-order binding and disagrees with `aw id request --team-auth`. |
| Verify a reconstructed payload. | Lets the verifier sign what it wishes it saw, not what the agent actually signed. |

## References

- `naapp-lib/src/aweb_naapp/runtime/team_auth.py` — shared FastAPI verifier implementation.
- `naapp-lib/tests/runtime/test_team_auth_envelope.py` — request-binding and refusal examples.
- `naapp-lib/tests/runtime/test_team_auth_vectors.py` — shared interop vectors.
- `naapp-lib/tests/runtime/test_awid_team_cache.py` — caching, publication and status failures.
- `docs/sot.md` Authentication envelope section — product/source-of-truth
  contract (`docs/sot.md:61-126` on main when this skill was written).
- `docs/vectors/team-auth-envelope-v2.json` and `test-vectors/` —
  byte-for-byte interop fixtures used by the tests.
