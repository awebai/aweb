# Member person declaration

Status: **contract.** AWID serves the record with the principal attestation
records (aweb-acgh.18.7), `docs/vectors/principal-attestation-v1.json` freezes
it, and `aweb_naapp.runtime.attestation.read_member_person` reads it. L1
(aweb-acgg.21) publishes the record, and the C2 `member_session` adapter
(aweb-acgg.8) reads it.

## Why it exists

A `member_session` approval (D1, [agent-pages.md](design/agent-pages.md) §4)
is safe only if the member account belongs to one natural person, rather
than being shared by several people or driven by an agent. Nothing in a
team-auth request or in a [principal attestation](principal-attestation.md)
says that. This record is the team controller's declaration that one
certificate's member is one natural person. It is a declaration, not
detection: it cannot notice a shared login.

## Authority

The team controller, holding the current team key, is the only party that can
make the declaration, as it is the only party that certifies members
([awid-sot.md](awid-sot.md), Certificates). A hosted deployment makes it
through the owner's designation or invitation act (L1). A self-custodial
controller signs it with its own team key.

## The record, `aweb.member-person/1`

It uses the signed-bytes form of [principal-attestation.md](principal-attestation.md):
`"aweb.member-person/1\n" || canonical_json(record)`, signed with the team
key.

```json
{
  "v": 1,
  "type": "aweb.member-person",
  "team_id": "backend:acme.com",
  "team_did_key": "did:key:z6Mk…",
  "certificate_id": "…",
  "member_did_key": "did:key:z6Mk…",
  "single_person": true,
  "issued_at": "2026-10-20T12:00:00Z"
}
```

- It is keyed by `certificate_id`. `member_did_key` must equal the
  certificate's.
- `single_person`: `true` declares one natural person. `false` withdraws the
  declaration.
- **Revocable.** Unlike member custody, the declaration can change while the
  key stays the same, for example when the owner re-designates who holds the
  seat. A newer record supersedes the stored one, and `single_person: false`
  revokes it. Revoking the certificate also ends it.
- **Publication:** `PUT /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/person`
  with `{record, signature}` and team-controller authority. AWID verifies the
  signature against the current team key, requires `team_did_key` to be that
  key, and requires the certificate to exist in that team with that
  `member_did_key`. It refuses an `issued_at` more than five minutes ahead of
  its clock. A byte-identical re-publish succeeds. Any other record must have
  an `issued_at` newer than the stored one.
- **Read:** `GET` on the same path, anonymous for public and private teams. It
  returns `{record, signature}` exactly as stored. An unknown team, an unknown
  certificate and a certificate without a record get the same `404`.
- **Privacy.** The anonymous read tells anyone who knows a `certificate_id`
  whether the controller declares that member to be one natural person. It
  reveals no identity, name or contact. The disclosure follows the same
  anonymity choice as certificate status and the custody record.
- **Team-key rotation** re-signs these records with the custody records, on
  the atomic path of [principal-attestation.md](principal-attestation.md) §5.
  On the non-atomic path, readers refuse in the window, and a stale record is
  never read as forgery.

## Reading it

A relying app reads the record after team-auth v2 verification, from the same
registry and against the current team key, exactly as principal-attestation
§4 step 6 reads custody:

1. A record signed with an old team key: `member_person_record_stale`.
2. A bad signature, a field that differs from the verified certificate, or an
   unknown field: `member_person_invalid`.
3. Absent, or `single_person: false`: the member is **not** declared to be one
   person.
4. A registry failure: `authority_unavailable`.

Records are cached for at most 60 s with no expired fallback.

**The C2 `member_session` adapter refuses an approval unless the record is
present, valid and `single_person: true`.** Absence never means yes.

## What this does not do

- It does not prove that one person uses the account. It records the
  controller's statement that one does.
- It names no person. The approval primitive's own records say who approved.
- It grants nothing by itself. It is one precondition of `member_session`
  approvals.
