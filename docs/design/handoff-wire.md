# The handoff on the wire

Status: **proposed** (aweb-acwd.4.6 for `aw`, aweb-acwd.4.2 for `aweb_naapp`).
It is not frozen until both sides ACK. It fixes the field names, encodings and
refusals that [Human confirmation started from `aw`](human-confirmation-from-aw.md#the-handoff)
leaves open. Every rule of that contract stands, and where this text and the
contract differ, the contract wins.

The handoff spans the installation's two pinned origins:

- `A`, the app origin: the manifest's `origin`, where team-auth is admitted;
- `O`, the human origin: `owner_acts.origin`, which refuses every team-auth
  header ([The handoff](human-confirmation-from-aw.md#the-handoff)).

| Step | Origin | Request | Authentication | `aud` |
| --- | --- | --- | --- | --- |
| 1. Start | `A` | `POST /handoffs` | team-auth v2 as the holder | `A` |
| 2. Page | `O` | `GET /handoff/{id}` | the browser's own ceremony | none |
| 3. Result | `O` | `POST /handoffs/{id}/result` | code and verifier in the body; the ephemeral key's signature in console headers | `O` |
| 4. Session requests | `O` | the console's routes | the ephemeral key's signature in console headers | `O` |

`aw` sends each request only to its step's pinned origin, follows no redirect,
and builds every URL it opens from `O`. It takes none from a response. It
never sends a team-auth header to `O`.

## Encodings

- **JSON bodies:** UTF-8 JSON. Unknown fields are refused.
- **Times:** RFC 3339 UTC to the second (`2026-11-09T12:00:00Z`).
- **The ephemeral key:** an Ed25519 key that `aw` generates per handoff and
  holds only in memory. It is named by its `did:key`.
- **Signatures:** Ed25519 over the signed payload's exact bytes, in standard
  base64 with no padding.
- **The start is signed with team-auth v2** as the holder, exactly as any
  request `aw` makes to `A`.
- **Requests to `O` carry console headers:** `X-Console-Key`,
  `X-Console-Signature`, `X-Console-Timestamp` and `X-Console-Signed-Payload`.
  - The human origin's `split_origins` boundary refuses every `Authorization`,
    `X-AWEB-*` and `X-AWID-*` header before the app
    (`naapp-lib/src/aweb_naapp/runtime/origins.py`). So these requests carry
    none of them, and team-auth admission never sees them.
  - They reuse team-auth's signature, raw-target and canonical-JSON
    primitives, and nothing else of it.
- **`verifier`:** 32 random bytes in base64url with no padding (43
  characters). `verifier_sha256` is the lowercase hex SHA-256 of the
  verifier's ASCII text.
- **`code`:** the single-use loopback code. It is 32 random bytes in base64url
  with no padding. The app stores only its SHA-256.
- **`user_code`:** 8 characters from `BCDFGHJKLMNPQRSTVWXZ`, shown as
  `XXXX-XXXX`. The app compares it ignoring case and the hyphen.
- **`nonce`:** 16 random bytes as 32 lowercase hex characters.

## 1. Start: `POST A/handoffs`

`aw` signs this request with [team-auth v2](../team-auth-envelope-v2.md) as
the holder, with `aud` `A`. `A`'s existing team-auth admission verifies it and
its certificate, as for any request. An unsigned start is refused. It is
rate-limited as login is.

```json
{
  "v": 1,
  "purpose": "session",
  "client_key": "did:key:z6Mk...",
  "return": "loopback",
  "redirect_uri": "http://127.0.0.1:53817/callback",
  "verifier_sha256": "<64 hex>",
  "scope": {"installation_id": "<uuid>", "role": "secrets.owner", "principal": "did:aw:..."},
  "client_hostname": "laptop.local"
}
```

- `purpose` is `credential` or `session`.
- `return` is `loopback` or `user_code`. `redirect_uri` is required with
  `loopback` and refused with `user_code`.
  - A redirect URI must be exactly `http://127.0.0.1:<port>/<path>` or
    `http://[::1]:<port>/<path>`, where `<port>` is a decimal from 1 to
    65535 with no leading zero and `<path>` is unreserved characters and `/`
    only. Anything else is refused: `localhost`, `https`, userinfo, a query,
    a fragment, a backslash, any percent-encoding and any other spelling of
    the address. A refused URI is `400 redirect_uri_refused`. The app
    redirects only to the URI it stored.
- `scope` names the holding: (installation, role, principal).
  - It is required for both purposes. For `credential`, the page shows it and
    the registration is for that principal.
  - For `session`, it is the holder's scope that the session is for.
  - The app's adapter resolves it to its own B3 scope and exact approver
    subject. Nothing a caller sends becomes key-bound authority directly.
  - `scope.principal` must be the verified team-auth signer.
- `client_hostname` is the hostname as `aw` reports it. It is required with
  `user_code`, where the fallback page shows it, and optional with `loopback`.

**Answer: `201`.**

```json
{"handoff_id": "<uuid>", "expires_at": "<now + at most 10 min>", "user_code": "BCDF-GHJK", "interval": 5}
```

- `user_code` and `interval` (in seconds) are present only with `user_code`.
- With `loopback`, `aw` opens `O/handoff/<handoff_id>`. With `user_code`, it
  shows the code and `O/handoff`, where the human types the code. The URL
  never carries the code.

**Refusals:**

- `400 handoff_invalid`: a malformed body, an unknown field, or a missing or
  forbidden member.
- `400 redirect_uri_refused`.
- `403 scope_not_signer`: `scope.principal` is not the verified signer.
- `401 console_session_required`: a `session` start for a holding the signer
  still holds but that has no credential able to log in, such as during a
  replace's cooling-off.
- `403 role_not_held`: a `session` start for a scope in which the signer
  holds no current holding. It is final.

`aw` never renews on a start refusal. A refused start, whether the
command's first or its one renewal, ends the command, and `aw` reports the
code.
- `409 fallback_unavailable`: a `session` start with `user_code` that the app
  cannot serve ([Fallback](human-confirmation-from-aw.md#the-handoff)).
- `429 handoff_rate_limited`.
- A team-auth refusal is team-auth v2's own answer.

A `credential` handoff grants nothing, so for it an unknown installation or
role is refused only later, by the page's ceremony.

### 1a. A session start by the holder's direct child (proposed; acxy.1/.2/.5)

Status: accepted direction (aweb 20173df8, Athena, servers, console,
human-kind), folded into the next acxy.1 delta for one review; not frozen.

A `session` start may be signed by H, as above, or by a requester Q: an agent
whose freshly verified ID chain has H as its **direct** parent. This admits Q
only to prepare this one session handoff. Q gets no H signing authority,
session, holding, membership, grant or approval. Every other purpose,
including `credential`, keeps the same-signer rule.

**What Q sends:**

- team-auth v2 as Q, with Q's OWN current team certificate in
  `X-AWID-Team-Certificate`, as for any request. Q is therefore a current
  member of the installation's team. A registered non-member laptop is refused
  by team-auth's own admission until a separately classified possession-proof
  surface is specified. This change adds none.
- Q's ID chain in `X-AWID-ID-Chain`, with the existing encoding
  (`awid.EncodeIDChainHeader`).
- The start body exactly as in section 1, with `scope.principal` = H and
  `return` = `loopback`. It carries no certificate of H, and a
  `holder_certificate` member is refused. The `user_code` fallback is not
  available when Q signs, so the code always goes to the loopback on the
  browser's own machine.

**What the app checks,** before creating anything, all from current evidence:

1. Q's team-auth, as today.
2. Q's chain verifies for subject (Q's `did:aw`, the `did:key` team-auth
   verified), with status evidence no older than the existing 60-second
   freshness bound. The issuer of Q's own certificate (its direct parent) is
   a human whose stable ID equals `scope.principal`, and that issuer's own
   verified kind is `human`. The edge is current (not revoked, current head). A deeper descendant, or a chain naming another
   parent, does not qualify.
3. H's membership evidence is the certificate the app already retains with
   H's holding (stored by the designate or replace that bound it, refreshed by
   H-signed paths; aweb decision (A), b2eae523). It is verified at use exactly
   as a holder's certificate is: under the team's current key, naming the
   installation's team and `member_did_aw` = H, with a published and unrevoked
   status, and H's own kind `human`. No usable retained certificate is
   `principal_not_member`; H refreshes it through an H-signed path. Q can't
   supply or replace it. That includes a retained certificate that is no
   longer current because H's membership certificate was renewed or replaced
   afterwards: the start refuses `principal_not_member` and never falls back to
   anything in Q's request.
4. The scope resolves to H's current holding, as today.

**Refusals:**

- `400 handoff_invalid`: the body carries `holder_certificate`, or uses
  `return: user_code` when the signer is not H.
- `403 scope_not_signer`: the signer is neither H nor a verified direct child
  of H. That covers a missing chain, another parent, a deeper descendant, and
  a revoked or stale edge.
- `403 principal_not_member` / `403 principal_not_human`: the retained
  certificate's checks, as today, including no usable retained certificate.
- `503 principal_status_unavailable`: chain or certificate status evidence
  cannot be read. This fails closed and is retryable.
- `403 role_not_held`, `401 console_session_required` and the rest of
  section 1's refusals apply unchanged.

**The result is unchanged.** It is released once, only to a caller holding
the single-use code (from the loopback on the browser's own machine), the
verifier preimage and a signature by the ephemeral key the start registered
(section 3). The session is H's, bound to that key, and it retains the
verified certificate of H's holding as its membership evidence. The handoff records Q, but only for display and audit.
The page's state route (`GET /handoff/{id}/session`) adds
`requester: {id, address, key_fingerprint}`, and the page shows Q separately
from H before H's app-RP LOGIN and the explicit Allow.

**aw:** a holder command run in Q's identity home takes H from Q's installed
chain (its direct parent), shows both, and signs as Q. With no qualifying
requester, aw refuses `requester_missing` and names the onboarding command. On
`principal_not_member` from a start Q signed, aw says that the app's retained
record of H's team membership is not current (for example after H's
certificate was renewed), and that it is refreshed only by a path H signs, never
by Q. Today that path is the owner's `human-credential.replace`, whose delivery
body carries H's current certificate.

Onboarding (`aw id create --human-parent H`) issues the laptop agent under H
with H's one live approval. It does not make the agent a team member. Q gets
its membership separately, through the team's agent admission: an admission
under the team's protected admission policy (`GET /protected-admission-policies`)
or a team-controller admission with its own live approval. Until then, a
start by Q is refused by team-auth.

## 2. The ceremony and the loopback redirect

The page runs the purpose's ceremony with B3's routes, then redirects the
browser to the stored URI:

```
http://127.0.0.1:53817/callback?handoff_id=<uuid>&code=<code>
```

- `aw` accepts exactly one `GET` on the exact path it registered. The query
  must carry exactly one `handoff_id`, equal to the one it started, and
  exactly one `code` in its canonical 43-character encoding. A missing,
  repeated or extra parameter is refused.
- It answers that request with a short page telling the human to return to
  the terminal. Every other request gets `404`, and nothing is read from it.
- The listener closes after the first accepted callback or at `expires_at`.
- With `user_code`, there is no redirect. The page says the handoff is
  complete, and `aw` learns of it from the result.

### What binds the result (the app's duty)

A result comes only from this handoff's own B3 ceremony. It never comes from a
subject or evidence reference that a caller supplies, or from a cookie that
existed before the handoff.

- **`credential`:** the WebAuthn challenge is bound to the handoff.
- **`session`:** the verified login and the human's explicit allow are bound
  to this handoff and its scope. No result can be collected before that
  binding exists.
- **Browser writes:** the page's completion writes are same-origin and carry
  CSRF protection.

None of this adds a field to `aw`'s requests.

## 3. Result: `POST O/handoffs/{handoff_id}/result`

The body is `{"v": 1, "code": "<code>", "verifier": "<verifier>"}`. With
`user_code`, `code` is absent.

The ephemeral key signs it:

```
X-Console-Key: <client_key>
X-Console-Signature: <signature>
X-Console-Timestamp: <timestamp>
X-Console-Signed-Payload: <base64url canonical JSON, no padding>
```

The signed payload is the canonical JSON of
`{"v": 2, "auth": "handoff-result", "aud": O, "method": "POST", "path": "/handoffs/<id>/result", "handoff_id": "<id>", "body_sha256": "<hex>", "timestamp": ..., "nonce": ...}`.

The app checks all of these before it releases anything:

- the key is the stored `client_key`;
- the payload matches the live request;
- the timestamp is within 300 seconds;
- the handoff has not expired and is completed;
- `SHA-256(verifier)` is the stored `verifier_sha256`;
- with `loopback`, `SHA-256(code)` is the stored code hash.

It then releases the result once, marking it released in the same
transaction.

**Answer: `200`.** The two purposes have distinct shapes.

```json
{"purpose": "credential", "credential": {"credential_id": "<b64url>", "public_key": "<b64url COSE>", "rp_id": "<O's hostname>"}}
```

```json
{"purpose": "session", "session_id": "<opaque>", "expires_at": "<at most 15 min>", "csrf_token": "<opaque>",
 "scope": {"installation_id": "...", "role": "...", "principal": "..."}}
```

- The `credential` fields use exactly the encoding of `credential_sha256`'s
  preimage ([Three acts](human-role-holders.md#three-acts)).

**Refusals:**

- `409 handoff_pending`, only with `user_code`, until the ceremony completes.
  `aw` waits `interval` seconds between attempts and stops at `expires_at`.
- `403 handoff_refused` for every other fault: a wrong key or signature, a
  stale timestamp, a wrong code or verifier, an expired handoff, a released
  handoff, or an unknown id. They are one answer, so a guess learns nothing.
- `429 handoff_rate_limited`.

## 4. Session requests

Every console request in a `session` handoff carries:

```
X-Console-Key: <client_key>
X-Console-Signature: <signature>
X-Console-Timestamp: <timestamp>
X-Console-Signed-Payload: <base64url canonical JSON, no padding>
X-CSRF-Token: <csrf_token>                       (on every non-GET)
```

**The signed payload** is team-auth v2's request-bound object with the session
id in place of `team_id`, plus a nonce, under its own `auth` value.

Its field set is exactly `v: 2`, `auth: "handoff-session"`, `aud`, `method`,
`path`, `session_id`, `body_sha256`, `timestamp` and `nonce`:

- `aud` is exactly the app's configured `O`;
- `path` is the actual raw request target, including the query;
- `body_sha256` is the lowercase hex hash of the actual decoded body;
- `timestamp` equals `X-Console-Timestamp`.

A result payload's field set is exactly the one in section 3. Neither carries
`team_id`, and a field outside its set is refused.

A session action builds its request by the version 2 tool rules, with one
difference: a `json`-mode `POST` with no body member sends exactly `{}`, not an
empty body, because the console's JSON routes read an object. A `GET` sends no
body.

The session id travels only inside the signed object. No cookie or bearer
header stands in for it. The app uses that untrusted id only to look the
session up. Only after it has checked the stored ephemeral key, the signature
and every field does it treat the request as that console session.

**The app checks,** in order:

1. the session exists, has not expired and is bound to this `client_key`;
2. the signature and the payload against the live request;
3. the timestamp is within 300 seconds;
4. the nonce has not been seen in this session. The nonce is kept until the
   session ends, which is at most 15 minutes, so longer than the window;
5. the CSRF token;
6. the principal is still a current team member of human kind.

**Refusals:**

- `401 console_session_required` for steps 1 to 5. A replayed nonce is one of
  them. It is the code the console already returns without a session, and
  the one on which `aw` renews the session through a fresh handoff
  ([human confirmation from aw](human-confirmation-from-aw.md)). Because the
  code is merged, `aw` renews on a signature or replay fault too. That stays
  safe because a confirm is sent at most once across a renewal.
- `403 role_not_held`: the session's holding was revoked. It is final, and
  `aw` never renews on it. A session whose login credential a
  `human-credential.replace` has retired is not this: the principal still
  holds the role, so the app answers `401 console_session_required`. During
  the cooling-off, the renewal's start is refused with the same code (section
  1) and the command ends. After it, the renewal's login needs the new
  passkey.
- `403 principal_not_member`.
- `403 principal_not_human`.
- `503 principal_status_unavailable`, the only retryable one. An unknown
  answer refuses, as [Use](human-role-holders.md#use) requires.

## Refusals stay merged

`handoff_refused` and `console_session_required` each cover every signature, key,
expiry, release and replay fault, so a probe learns nothing. The answer never
says whether a handoff expired or was already used. The three
principal refusals stay distinct, because human-role-holders.md names them
and they separate a final refusal from authority that is unavailable.
