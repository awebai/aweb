# Member attribution v1

Status: **contract candidate; implementation follows review**. The public
fixtures are [`vectors/member-attribution-v1.json`](vectors/member-attribution-v1.json).
This adds a controller statement about the human behind a member. It changes
neither v1 certificate bytes nor existing membership, message, custody or grant
signatures. A human needs no signing key. A verifier trusts the controller's
login/email validation, as it trusts that controller to admit members.

## 1. Record and signed bytes

The type is `aweb.member-attribution`, version `1`. Every field shown below is
required; unknown fields, duplicate JSON keys, floats and invalid types refuse.
`parent` and `human` may be JSON null. There are no omitted/defaulted fields.

```json
{
  "v": 1,
  "type": "aweb.member-attribution",
  "team_id": "engineering:example.com",
  "team_did_key": "did:key:...",
  "certificate_id": "00000000-0000-4000-8000-000000000001",
  "member_did_key": "did:key:...",
  "human": null,
  "parent": null,
  "how": "none",
  "since": null,
  "issued_at": "2026-10-26T00:00:00Z"
}
```

`team_id`, controller key, certificate id and member key bind to the verified
certificate/current team authority. Use canonical team ids and canonical
lowercase UUID certificate ids. The member may be local or global: a local
member requires no did:aw, and the exact certificate/key is the agent binding.

`parent`, when present, has exactly `certificate_id` and `member_did_key` and
names the authenticated spawning member in this team at creation. It is
historical evidence, not a requirement to fetch a live parent on every check.
An invite issuer is not the parent without authenticated creation authority
for that member. Org-owner authority in a different team is not evidence of a
target-team parent or of a human in this team.

`human` is either null or exactly
`{"domain":"example.com","fingerprint":"<hex>"}` for every team. Section 2
defines these bytes. A record never contains the readable email.

`how` is `login`, `email`, `inherited` or `none`. Null human requires `none`
and null `since`; an attributed human requires one of the first three and a
nonnull `since`. `inherited` requires a parent. Direct login/email may preserve
an existing parent when a previously human-less agent is claimed. `since` is
when this member acquired its human, never before its membership existed;
`issued_at` is this signature's publication time. Both use RFC 3339 UTC, ASCII
digits, seconds, `Z`, with `since <= issued_at`. Parent creation does not
pretend that the human freshly authenticated for each descendant.

The signature and canonicalization match the
[principal signed-record family](principal-attestation.md#signed-bytes):

```text
signing_bytes = UTF8("aweb.member-attribution/1\n") || canonical_json(record)
signature = base64url_no_padding(Ed25519(team_private_key, signing_bytes))
signed_record = {"record": record, "signature": signature}
```

The prefix ends with one LF byte. Canonical JSON sorts keys, has no whitespace,
uses UTF-8 without ASCII escaping, and accepts only the stated field types.
Raw transport bytes must equal re-canonicalization. Base64url has one canonical
encoding and the signature decodes to exactly 64 bytes. A 16 KiB maximum applies
to the encoded presentation header in section 4. Unknown versions/types refuse
as unsupported, not as a different valid record. The fixtures freeze complete
canonical bytes, signature, fingerprint and presentation encodings.

## 2. Validated email and privacy

The human id is the validated email. Version 1 normalizes by trimming ASCII
space/tab/CR/LF at the ends and lowercasing the whole address. It performs no
provider-specific transformations (no dot/plus removal). The v1 wire email is
an ASCII mailbox with exactly one `@`, nonempty local part, and a lowercase DNS
domain with no trailing dot or whitespace. The existing operator validates
mailbox syntax/deliverability. Unsupported internationalized addresses must
not be guessed or rewritten into another human; baseline account/coordination
support is unchanged. A later email-profile extension needs reviewed vectors.

Let `E` be this normalized address and `T` the exact canonical `team_id`:

```text
fingerprint = lowercase_hex(SHA256(
    UTF8("aweb-human-v1\n") || UTF8(T) || 0x00 || UTF8(E)))
domain = E's substring after @
```

This uses a public per-team scope, not a secret salt. Newline and NUL are
literal bytes; neither may occur in T or E. A verifier knowing an email
normalizes it and recomputes this fingerprint for T. The domain remains in
clear so a verifier without the email can make the company-scope check.
Matching a known email requires BOTH its domain and fingerprint to match;
otherwise the comparison reports `email_mismatch`, not that H is this email.

Records never contain the readable email. This prevents directly
listing addresses and cross-team hash equality, **not guessing attacks**:
someone who guesses an address can test it within a team. Do not describe this
as anonymous identity or as encryption. Controller-only storage may retain E
for delivery/inheritance and display to its own authorized viewers. A verifier
can display an email it already knows after matching it; otherwise it displays
the domain and fingerprint. No email or redemption secret enters the signed
record, registry read, message, header, log or error. No human directory or
unused DID/key is created.

A company claim means that the email domain is the team's namespace (exact
DNS-name equality) or that the verifier independently establishes this
controller's authority for that email domain using existing namespace authority.
An address at another domain is still a controller-attributed human, displayed
as **asserted by the team controller**, not as that domain's company person.
A suffix match, an email-supplied hostname, or the record's own claim alone
never establishes namespace authority. The controller's validation remains the
personhood trust root; DNS alone does not verify a mailbox.

An email change is leaving: retire the old human's agents and admit/claim new
agents with the new email. There is no rename or H-to-H update.
`(T, fingerprint, domain)` identifies the human in this team.

## 3. Publish, fetch and monotonic updates

The path is
`/v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/attribution`.
`PUT` accepts `signed_record` under the existing AWID controller-request
authentication, operation `publish_member_attribution` bound to this certificate.
Only the CURRENT team controller writes. AWID locks the team key and active
certificate, verifies the signature and exact member binding, then stores the
record. Reuse the existing signed-record checks, not client-provided human
fields as authority. A time over five minutes ahead refuses.

Publication rules under one write lock:

- Missing record may become an explicit null-human record or attributed H.
- Null human may become H, with a newer `issued_at` and `since` equal to the
  accepted login/email claim time. Preserve the member/parent binding.
- H never becomes null or another fingerprint/domain. Conflicting writes
  refuse with 409. Two competing first claims cannot both succeed.
- Byte-identical retry succeeds. An H record's `how`, `since` and parent stay
  fixed; key-rotation re-signing may change only controller key and `issued_at`.
- A fresh certificate for the same established member receives a freshly
  bound record preserving H and its known provenance; no further human auth.
  Reuse/import/projection cannot invent a new creator or replace known H.

`GET` returns exactly `signed_record`. Use the SAME team certificate visibility
gate: anonymous public teams; private teams require controller, current member
or trusted service read authority. Existing anonymous person/custody endpoints
are not a precedent for making attribution anonymous. A missing record for an
otherwise readable certificate returns 404 (unknown), not null-human. A
missing/inaccessible team must not disclose its attribution via errors.

Include attribution in the existing signed-record enumeration and atomic team
key-rotation set as `member_attribution`, keyed by certificate id. Re-sign with
the new team key without changing H/parent/how/since. A released non-atomic
rotation remains accepted; old-key records are stale and fail closed until
re-signed. A released atomic client omitting the new `member_attribution` field
also retains its previous rotation behavior for the record families it knows;
attribution may remain stale until re-published. An explicitly supplied new
field requires the complete attribution set. New clients always include it.
Do not make an old, otherwise valid rotate request fail merely because the
team has since acquired attribution records. A stale record supplies no verified
human (display unknown/stale); the next rotation by an upgraded client re-signs
the full set and clears it. There is no automatic re-signing job.

## 4. Presentation and verification

An agent may present proof next to its existing certificate. On HTTP use the
optional `X-AWEB-Member-Attribution` header:

```text
base64url_no_padding(canonical_json({"certificate": certificate,
                                   "attribution": signed_record}))
```

The certificate is the unchanged existing certificate object. This header does
not change team-auth v2 or identity-only authentication, add a new principal,
or grant membership. Verify the actual request/member signature first. For
identity-only mail, the proof's member key must equal the independently verified
message/request author and its team must equal the selected delivery team.
Never use the certificate in this optional proof to switch the auth lane/team.

Mail/chat senders use this same optional header; do NOT add a field to existing
signed payloads or encrypted inner/envelope bytes. A participant-authorized
message read may return the optional transport metadata `sender_attribution`
with the same `{certificate, attribution}` object. It is separate from the
signed message and E2EE ciphertext. A relay verifies the author/team/certificate
binding before forwarding it; a recipient checks it independently. Old servers
ignore the new header, old clients may omit it, and absence is unknown. No new
request-body field or mandatory field is added to released clients.

After ordinary certificate signature/current-team-key/revocation checks:

1. Decode canonical bytes; validate shape/signature; require exact
   certificate/team/member/controller binding. A mismatched, forged or malformed
   presented record refuses attribution (`attribution_invalid` or
   `attribution_binding_mismatch`), never becomes a verified human.
2. An old controller key yields `attribution_stale`; required authority
   unavailable yields `authority_unavailable`. Revoked/expired membership
   cannot gain human authority through a record. Use the existing certificate
   verifier's freshness; this contract does not relax stricter consumers.
3. A valid presented H is final for that certificate: no latest-attribution
   lookup. Verify namespace scope and, if comparing a known email, its
   fingerprint. The record's signature authenticates the controller's assertion
   that login/email validation occurred; it does not prove a fresh human gesture
   for the request, identity-key custody, or consent to arbitrary further acts.
4. Presented null-human or absent proof is NOT authoritative. A policy/audit
   receiver that needs attribution fetches the CURRENT record for the verified
   certificate, verifies it, and reports H, explicit no-human, or unknown (404).
   An unavailable fetch is unavailable, never verified no-human. `aw who`
   ALWAYS fetches, even when a cached/presented H exists.

This is the membership trust model: proof can travel with the member and dies
with certificate revocation. The email-domain scope check uses ordinary
namespace authority. Offline bundles are as-of the same membership authority
evidence/freshness, not a promise of current status forever. No team-level claim
record, new termination mechanism, action snapshots, human keys or tiers exist.
Human-owner powers additionally require that human's CURRENT membership; an
old H record cannot authorize a departed human during incomplete retirement.

## 5. OSS controller and email flow

AWID stores public signed facts and never receives controller private keys.
In self-hosted operation the team operator holds the team signing key, separately
from member keys, and enables an optional controller capability in its OSS
aweb application. Configure the team's key in operator-only storage (or an
equivalent signing callback), the controller's public confirmation origin, its
founding/root principal, and SMTP transport/from address. The namespace key is
not needed for each claim. A remote coordination server without this controller
authority may relay requests but cannot sign an attachment or invent H.

The public controller surface is:

- `POST /v1/attribution/claims`, signed by the selected existing agent under
  its normal member authentication, with `{email}`. The response reports a
  pending claim id/status, never the redemption token/link. Require founding/
  root authority for a first whole-team claim, not arbitrary member possession.
  The operator explicitly configures/records that root when provisioning the
  team; do not infer it from the first untrusted request.
- The controller generates a random unguessable token, stores only its digest
  with exact team, agent/certificate/key, normalized email, expiry and unused
  state, and sends the link itself by operator-configured SMTP. Tokens expire
  after 15 minutes. No SMTP or real human login means **email validation
  unavailable / no human**; showing the requesting agent a link is not proof.
- The link lands on that controller application's human confirmation page,
  `GET /v1/attribution/claims/confirm?token=...`. GET shows the exact team/agent
  and an approve form without consuming the token (mail link scanners are not
  approval). A browser POST to the same path confirms possession. Do not log or
  place the token in outgoing referrers. The token is never a member credential.
- On POST, lock/recheck token, exact current team/agent/key/certificate, root
  scope, no prior H and removal fences; check expiry AFTER the last lock wait.
  Consume once and record controller acceptance on the same connection as the
  durable signing/publication intent. Publish the signed record through the
  AWID API above; retry the SAME accepted result after publication failure,
  never assign a different email. No network I/O under database locks. Until
  signed publication succeeds, report pending/unavailable attribution, not a
  completed claim. A terminal conflict produces no changed attribution.

A logged-in browser is an alternative only in deployments with real human
authentication; use its authenticated account email, not a submitted human id.
No extra login is required to create agents from that session. Existing hosted
`aw claim-human --email` remains supported; operators may map it to the same
claim service, without replacing its released account-onboarding behavior.
No-org hosted signup/claim remains supported; org claim, team adoption,
ordinary human admission and seat checks remain separate operator policies.

## 6. Creation, inheritance and retirement

- **Human-less default:** create explicit null-human records where a controller
  creates membership without validated human/parent attribution. Standalone
  `aw id create` creates identity, not membership: attribution begins when a
  certificate is admitted, not with an invented team or human.
- **First team claim:** one root-authorized email/login approval covers the
  current explicitly approved human-less cohort. Persist that acceptance before
  publishing per-certificate none-to-H updates; fence concurrent spawns so they
  inherit H or join the covered cohort. An existing H refuses overwrite. No
  certificate reissue or team-level record; earlier starter remains unknown.
- **Spawn:** authenticate the actual parent via its current member credential
  and exact creation request. Resolve its current H; issue the child record
  with the same normalized email/fingerprint for this team and parent binding.
  No further human auth. A human-less parent yields null-human. A generic
  shared/team API key or mutable owner metadata is not proof of a parent/human.
  A controller retains its private validated email for cross-team re-hashing;
  without independently established target-team provenance, report unknown,
  never guess an email from another team's fingerprint or org-owner status.
- **Invites:** the issuer fixes `spawn` or `admission` at issuance. Untyped NEW
  invites from an attributed agent are spawn/inherit, or refuse; never an
  unattributed root/admission. Named-email admission requires team admission
  authority and a link bound to the intended child key/team/email; no active
  certificate before that email approval and child key proof. A token may be
  staged until the child key is known, but the confirmation is bound to that
  exact key. The inviter is forensic evidence, not an inherited parent.
  An authenticated human login can approve its own matching admission.
- **Legacy/reuse/projection/import:** preserve established attribution; absence
  is unknown. Pre-upgrade untyped tokens cannot be classified retrospectively.
  Existing credential/member reuse does not create a new start. API-key init
  without a validated human or authenticated attributed parent gains no guessed
  H from an account label. Existing membership/coordination remains supported.
- **Leaving/email change:** use retirement/revocation for that human's agents,
  including descendants and direct creations. Fence new children while removal
  proceeds; human-owner policy requires current human membership throughout.
  Do not set H to null or another email. Fresh replacement agents may be
  claimed. Global identity/other-team memberships and historical records remain.

## 7. Conformance and integration

The JSON fixture is a **contract-only corpus**, not evidence of a running
implementation. It includes real synthetic Ed25519 signatures, login/email
and inherited/no-human examples, email normalization/matching, canonical header
bytes, forgery/binding/shape refusals, monotonic writes and the fetch-on-none
procedure. Go and Python must consume these root bytes in the implementation
slice. Do not re-freeze old certificate/message vectors.

The accepting AWID/server must land before new clients rely on publication or
read support. Released clients without attribution remain valid, returning
unknown until fetched/backfilled by an explicit approved claim. Consumers that
require a human refuse missing/unavailable attribution, without changing normal
mail/tasks into universally human-required operations. Cloud consumes the same
public Python record/verification and controller APIs; no private OSS SQL or
duplicated wire contract. The implementation will expose pure normalization,
fingerprint, canonical signing/verification helpers and a caller-transaction
controller acceptance operation before Cloud adopts record writes.
