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
- `403 role_not_held`: a `session` start for a scope in which the signer
  holds no current holding. It is final, and `aw` reports it and stops.
- `409 fallback_unavailable`: a `session` start with `user_code` that the app
  cannot serve ([Fallback](human-confirmation-from-aw.md#the-handoff)).
- `429 handoff_rate_limited`.
- A team-auth refusal is team-auth v2's own answer.

A `credential` handoff grants nothing, so for it an unknown installation or
role is refused only later, by the page's ceremony.

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
  `aw` never renews on it. A credential superseded by a replace whose
  cooling-off has ended is not this: the principal still holds the role, so
  the app answers `401 console_session_required`, and the renewal's login
  needs the new passkey.
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
