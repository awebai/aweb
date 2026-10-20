# Principal attestation

Status: **contract proposal for aweb-acgh.18.7 (S6), not yet implemented.**
It turns the design in [secrets §4.6](design/secrets.md) into three wire
artifacts and one verification procedure. Vectors in `docs/vectors/` freeze it
once it is reviewed.

## Why it exists

A team-auth v2 request ([team-auth-envelope-v2.md](team-auth-envelope-v2.md))
proves that a request was signed with a certified member key. It does not say
who holds that key, or which human, if any, started the call
([product-authority-sot.md](product-authority-sot.md)). A custodial deployment
holds members' keys and signs as them, for example behind a hosted MCP endpoint.
A relying app that wants to treat those calls differently needs a signed
statement from the custodian. It must also be able to check that the
custodian really holds that member's key.

The attestation can prove only positive, custodial facts. A self-custodial
member carries no attestation, and the absence of one proves nothing, because a
key can be copied. No verifier, policy or tool may infer self-custody, or a
`dashboard` channel, from a missing attestation.

## Model

- **Custody.** A custodian is an operator that holds members' signing keys. It
  is named by an opaque `custodian_id` and signs attestations with one of its
  registered issuer keys.
- **Authority.** The team controller, holding the current team key, is the
  only party that can say a custodian holds a member's key. The custodian's own
  statement is not enough. Both AWID records below are signed with the team
  key, exactly as certificates are ([awid-sot.md](awid-sot.md), Certificates).
- **Transport.** The custodian attaches an attestation to each request it
  signs under custody. The attestation is bound to that one request.
- **Verifier.** The relying app verifies the team-auth request first, then the
  attestation against the two AWID records, using the registry and the current
  team key that verified the request.

## Signed bytes

All three artifacts use the same form:

```text
signing bytes = "<type>/1\n" || canonical_json(payload)
signature     = Ed25519(signing key, signing bytes)
```

The prefix ends in one literal newline byte. `canonical_json` is AWID's
(`awid/src/awid/signing.py`): keys sorted, no whitespace, UTF-8, integers only
(no floats), and duplicate keys refused on input. Verifiers re-canonicalize the
parsed payload and require the exact bytes they received. Each payload carries
its own `type` and `v`, and every prefix differs from a team certificate,
`aweb.team-server/1` and `aweb.owner-act/1`, so no artifact verifies as another.

Timestamps are RFC 3339 UTC strings with a `Z` suffix and second precision.

## 1. Team custodian record, `aweb.team-custodian/1`

It registers a custodian and its issuer keys for one team.

```json
{
  "v": 1,
  "type": "aweb.team-custodian",
  "team_id": "backend:acme.com",
  "team_did_key": "did:key:z6Mk…",
  "custodian_id": "custodian.example",
  "issuer_did_keys": ["did:key:z6Mk…"],
  "issued_at": "2026-10-20T12:00:00Z"
}
```

- `custodian_id`: 1–128 characters from `[a-z0-9.-]`. It is opaque, and
  relying apps compare it only for equality. An operator should use a domain
  it controls, so that ids from different operators do not collide.
- `issuer_did_keys`: zero to two distinct Ed25519 `did:key`s. Two keys allow an
  overlap during rotation. An empty list deregisters the custodian for this
  team.
- **Publication:** `PUT /v1/namespaces/{domain}/teams/{name}/custodians/{custodian_id}`
  with `{record, signature}` and team-controller authority. AWID verifies the
  signature against the current team key and requires `team_did_key` to be that
  key. It refuses an `issued_at` that is not newer than the stored record's, or
  more than five minutes ahead of AWID's clock.
- **Read:** `GET` on the same path, anonymous for public and private teams. It
  returns `{record, signature}` exactly as stored. An unknown team and an
  unknown custodian get the same `404`.
- **Rotation of the team key** invalidates every record signed with the old
  key: the team's custodian records and every member-custody record, one per
  custodial certificate, so the batch grows with the number of custodial
  members. The rotation re-signs and publishes all of them in the same
  operation, as it does for `aweb.team-server/1`. That applies to `aw`'s rotate
  flow and to a custodial deployment's rotation step. Until it finishes,
  verifiers refuse with `attestation_record_stale`, which fails closed but
  makes every attested call fail.

## 2. Member custody record, `aweb.member-custody/1`

It states that a custodian holds the key of one certificate.

```json
{
  "v": 1,
  "type": "aweb.member-custody",
  "team_id": "backend:acme.com",
  "team_did_key": "did:key:z6Mk…",
  "certificate_id": "…",
  "member_did_key": "did:key:z6Mk…",
  "custodian_id": "custodian.example",
  "issued_at": "2026-10-20T12:00:00Z"
}
```

- It is keyed by `certificate_id`. `member_did_key` must equal the
  certificate's.
- **The record is immutable once published.** A key a custodian has held stays
  custodial for its whole life, because the custodian could have copied it.
  The only way to end it is to revoke the certificate. A member who moves to
  self-custody gets a new key and a new certificate.
- **Publication:** `PUT /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/custody`
  with team-controller authority. AWID verifies the signature and the current
  team key, requires the certificate to exist in that team with that
  `member_did_key`, and requires the custodian to be registered for the team
  (§1). It accepts a byte-identical re-publish and refuses any other record for
  that certificate, with `409`. The one exception is a re-signature after a
  team-key rotation: the same fields apart from `team_did_key` and `issued_at`.
- **Read:** `GET` on the same path, anonymous. An unknown team, an unknown
  certificate and a certificate without a custody record get the same `404`,
  as certificate status does.
- **Privacy.** The anonymous read tells anyone who knows a `certificate_id`
  whether that member's key is held by a custodian, which in practice means
  hosted. Certificate status does not reveal that. The disclosure follows the
  same anonymity choice as certificate status and the team-server record.

## 3. The attestation, `aweb.principal-attestation/1`

The custodian sends it with the request it signed:

```text
X-AWEB-Principal-Attestation: <base64url(payload bytes)>.<base64url(signature)>
```

`payload bytes` is the canonical JSON without the prefix, and base64url has no
padding. The header is at most 4096 bytes.

```json
{
  "v": 1,
  "type": "aweb.principal-attestation",
  "team_id": "backend:acme.com",
  "certificate_id": "…",
  "member_did_key": "did:key:z6Mk…",
  "custody": "custodial",
  "custodian_id": "custodian.example",
  "issuer_did_key": "did:key:z6Mk…",
  "channel": "mcp_l2",
  "human_principal": "opaque-subject-handle",
  "session_id": "opaque-session-id",
  "iat": "2026-10-20T12:00:00Z",
  "exp": "2026-10-20T12:05:00Z",
  "request_binding": "<64 lowercase hex>"
}
```

- `custody`: `custodial` is the only value. The field exists so that a later
  version can add a value without changing the meaning of this one.
- `channel`: `mcp_l2`, `dashboard` or `api`.
  - `mcp_l2`: the custodian's hosted MCP endpoint.
  - `dashboard`: a page the custodian renders to a signed-in human.
  - `api`: any other call the custodian signs.
  The manifest v2 call-time check reads this field (aweb-acgg.9).
- `human_principal`: optional. It is an opaque handle scoped to the issuer for
  the OAuth subject, 1–128 characters from `[A-Za-z0-9._:-]`. It is never an
  email address, and a value containing `@` is refused.
- `session_id`: required, with the same character rule.
- `iat` and `exp`: `exp` is after `iat` and at most 300 s later.
- `request_binding`: the SHA-256 of the exact team-auth signed-payload bytes
  of the request it accompanies, that is the decoded `X-AWEB-Signed-Payload`.
  An attestation therefore applies only to team-auth v2 requests. On a request
  without a v2 signed payload (compact v1), it is refused with
  `attestation_binding_mismatch`, and it is never bound to anything else.
- Unknown fields are refused.

## 4. Verification

A relying app runs these steps after team-auth v2 verification has produced
the verified certificate, the registry and the current team key. Every step
fails closed.

1. **Presence.** No header means no attestation. The verifier returns "none";
   it never returns a default channel. A policy that requires an attestation
   then refuses with `attestation_required`.
2. **Shape.** Split, decode, parse, reject duplicate keys and unknown fields,
   re-canonicalize and compare bytes, and check every field's type and range.
   Failure: `attestation_invalid`.
3. **Request.** The request carries a v2 signed payload; a compact v1 request
   with an attestation is refused. `team_id`, `certificate_id` and
   `member_did_key` equal the verified certificate's. `request_binding` equals
   the SHA-256 of this request's signed-payload bytes. Failure:
   `attestation_binding_mismatch`.
4. **Time.** `iat` is at most 60 s ahead of the verifier's clock, `exp` has not
   passed, and `exp - iat` is at most 300 s. Failure: `attestation_expired`.
5. **Signature.** Verify the attestation signature with its own
   `issuer_did_key`. This is local and cheap, so a forged attestation never
   causes a registry read. Failure: `attestation_invalid`.
6. **Member custody.** Read the §2 record for `certificate_id` from the same
   registry. Require its signature under the current team key, `team_did_key`
   equal to that key, and `certificate_id`, `member_did_key` and `custodian_id`
   equal to the attestation's. Absent: `attestation_issuer_unregistered`.
   Signed with an old team key: `attestation_record_stale`.
7. **Custodian.** Read the §1 record for `custodian_id` the same way, and
   require `issuer_did_key` to be in `issuer_did_keys`. Absent, or the key not
   listed: `attestation_issuer_unregistered`. Old team key:
   `attestation_record_stale`.

A valid signature by a key that is not registered fails at steps 6 and 7.

A registry read that fails, times out or returns anything but `200` or `404`
refuses with `authority_unavailable`. Records are cached per
`(registry origin, team_id, record key)` for at most 60 s, with no expired
fallback, as for certificate status.

On success the verifier returns `custodian_id`, `channel`, `human_principal`
and `session_id`. It never returns a statement about self-custody.

The refusal codes are distinct so that operators can tell a forged or
malformed artifact, a stale record, an unregistered custodian and a registry
outage apart.

## What this does not do

- It does not prove self-custody, or that a request did not come through a
  custodian.
- It does not identify a natural person. `human_principal` is the custodian's
  assertion about its own OAuth session.
- It grants nothing. A relying app applies its own grants and policy after
  verification, and a manifest's `invocation_contexts` only narrows which
  tools a channel may call.
- A self-hosted surface host cannot issue `dashboard` attestations until it is
  registered as a custodian through §1 and §2. That is a later item.
