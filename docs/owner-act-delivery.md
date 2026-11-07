# Owner-act delivery for app acts

Status: **specified, not shipped**. Owner: the aweb OSS hooks lane
(aweb-acgh.16.38). Its design choices await Juan's ruling at design review
(see [Summary for Juan](#summary-for-juan)). This document is the source of
truth for how a client delivers an app owner act (`app-role.designate`,
`app-role.revoke` and `app-credential.recover`, defined in
[the owner-act contract](owner-act.md)) to the naapp that verifies it, with no
per-app code in the client. Its vector is
`docs/vectors/owner-act-delivery-v1.json`.

The owner-act contract fixes the signed artifact and its verification. This
contract adds what that one leaves to the transport:

- where the app's human origin is declared, and so what `aud` is;
- which app-local role token the act names, and who issues it;
- how the inputs that are not in the act (the contact, the principal) travel;
- the one delivery route, and its refusals.

## Summary for Juan

| Choice | Taken | Rejected, and why |
| --- | --- | --- |
| Where the human origin and the owner-designated roles are declared | `owner_acts` in [manifest version 3](app-manifest.md#manifest-version-3), served as a catalog variant beside version 2 | A field in version 2 breaks every released `aw` from 1.36.46 to 1.36.56, which refuse unknown fields. A separate, unpinned well-known document lets the console origin, where contacts go, change after install without review. |
| How the client gets the role token the act names | The app issues it: a prepare call records a pending row and returns the exact subject to sign | A client-side derivation rule cannot be generic: logs' reader token is random by design, because it is public in governance events and must not be derived from the contact. |
| Who may ask for a pending subject | A team-auth member call to a declared agent tool, with a grant scope declared per role | An anonymous call on the console origin would loosen logs' existing rule that only a granted member opens a reader slot. |

The pinned manifest is then the only reviewed source of what an owner signs
for and where the contact goes, as it already is for hook-binding acts.

## The model

- **Authority.** Only the owner act is authority. It is signed by the team's
  current controller key ([Who signs](owner-act.md#who-signs)). Nothing in
  this contract adds or relaxes an owner-act check.
- **The app chooses the role token.** An app-local role holder is named by a
  token that the app issues: the B3 scope the holder enrols under. The client
  never derives one.
- **A pending row grants nothing.** Prepare records what the owner is about to
  sign. Only an owner act that names that row exactly takes effect.
- **The human origin is the audience.** The act's `aud` is the declared
  `owner_acts.origin`, and the act is delivered there. That origin serves
  passkey sessions and never admits team-auth, so its hostname differs from
  `app.origin`'s. A port does not separate them, because cookies ignore ports.

## Declaration

A version 3 manifest declares `owner_acts`; [app-manifest.md](app-manifest.md#manifest-version-3)
fixes its validation codes. An app with no owner-designated role omits it.

```json
{
  "owner_acts": {
    "origin": "https://console.logs.example",
    "roles": [
      {
        "name": "logs.reader",
        "label": "Log reader",
        "description": "Reads the team's audit log in a passkey session on the console.",
        "acts": ["app-credential.recover", "app-role.designate", "app-role.revoke"],
        "principal": "refused",
        "prepare_tool": "owner-act-prepare"
      }
    ]
  }
}
```

- `origin` is an `https` or `http` origin with no userinfo, path, query or
  fragment, and its hostname differs from `app.origin`'s. It is the `aud` of
  every act for this app, compared byte for byte.
- `roles` has 1 to 16 entries, unique by `name`.
  - `name` follows the designatable role grammar (dot-separated lowercase
    segments, at least two, `[a-z0-9][a-z0-9_-]*` each) and is at most 31
    bytes, so that every token fits the owner-act token grammar.
  - `label` and `description` follow the rules of the version 2 `roles`
    field: 1 to 128 and 1 to 512 characters, with no C0, C1 or bidi control.
    Every surface that shows the role shows the pair of app and name.
  - `acts` is a nonempty set of app acts, ascending by code point with no
    repeat.
  - `principal` is `required` when the role binds a team member's principal
    (a secrets owner), or `refused` when it does not (a logs reader).
  - `prepare_tool` names a tool of the same manifest whose method is `POST`,
    whose `invocation_contexts` are exactly `["agent"]`, whose `body.mode` is
    `json`, and whose params are exactly the five prepare fields below, each
    `in: body`. The tool's `scopes` are the grant a member needs to prepare
    for this role. Several roles may name one tool.
- `owner_acts` and the version 2 `roles` field are separate. The version 2
  field declares roles a team admin designates; `owner_acts` declares roles
  only an owner act designates.

## Role tokens

A role token is the role's `name`, a dot, and 32 to 40 lowercase hex
characters: `logs.reader.` followed by 32 hex, `secrets.owner.` followed by 40.
It is the owner-act subject's `role` and the B3 scope the holder enrols under,
and it is the value the `post-governance-hook` `role` field carries.

- The app chooses the suffix, and the token never changes for that holder.
- The suffix is never derived from the contact: the token is public in
  governance events, and the contact is not. A suffix derived from the
  installation, the team and the member's principal, as secrets derives its
  owner scopes, is allowed.

## Prepare

The member's client calls the role's `prepare_tool` on `app.origin` with
team-auth, like any agent tool. The runtime authorizes the call against the
tool's scopes and the team's grant, unchanged.

Request body, a JSON object with exactly these fields:

| Field | `app-role.designate` | `app-credential.recover` | `app-role.revoke` |
| --- | --- | --- | --- |
| `act` | required | required | required |
| `role` | the declared role `name` | same | same |
| `contact_sha256` | required | required | refused |
| `principal` | required if the role's `principal` is `required`, else refused | same | same |
| `holder` | refused | the holder's token, when `principal` is `refused` | the holder's token, when `principal` is `refused` |

A refused field is absent; JSON `null` is refused. `contact_sha256` is the
lowercase hex SHA-256 of the UTF-8 contact. `principal` is a team member's
`did:aw` or `did:key`. For a role that binds a principal, the principal names
the holder in every act, and `holder` is refused.

The app then:

- **designate** records a pending row binding the installation, the team, a
  token, the contact hash and the principal, if any;
- **recover** finds the current holder and records a pending recovery row
  binding its token and the contact hash;
- **revoke** finds the current holder and records nothing.

Pending rows are keyed by token and contact hash together. A second prepare
for the same token with another contact hash adds a row and never replaces the
first. A pending row lives at least ten minutes and at most 24 hours. The app
consumes it once, in the transaction of the act's effect.

Response `200`:

```json
{
  "act": "app-role.designate",
  "aud": "https://console.logs.example",
  "subject": {
    "app_id": "logs",
    "installation_id": "inst-1",
    "role": "logs.reader.00112233445566778899aabbccddeeff",
    "contact_sha256": "<64 hex>"
  },
  "expires_at": "2026-11-07T13:00:00Z"
}
```

`subject` is the exact owner-act subject to sign. `expires_at` is the latest
time the app accepts an act naming it.

| Status | `detail` | When |
| --- | --- | --- |
| 400 | `request_invalid` | The body breaks the table above, the role is not declared, or the act is not in the role's `acts`. |
| 404 | `holder_unknown` | Recover or revoke names no current holder of this installation. |
| 429 | `owner_act_prepare_rate_limited` | The member's prepare budget is spent; the response carries `Retry-After`. |
| as given | the installation's code | The installation is not admitted. |

The runtime's authorization refusals (missing grant, wrong context) are
unchanged.

## What the client checks, shows and signs

Before showing anything to the owner, the client refuses a response, with the
local code `prepare_mismatch`, unless all of these hold:

- `act` is the act it asked for;
- `aud` equals the pinned manifest's `owner_acts.origin` byte for byte;
- `subject` has exactly the fields owner-act/1 requires for the act;
- `subject.app_id` is the pinned manifest's `app.id`;
- `subject.installation_id` is the installation the client resolved for this
  app and team;
- `subject.role` is the declared role name, a dot and 32 to 40 lowercase hex
  characters, and equals `holder` when the request names one;
- for designate and recover, `subject.contact_sha256` is the SHA-256 the
  client computed from the contact the owner typed.

The client shows the owner the app (id and origin), the role as the pair of
app and `label`, the act, the contact or the holder, the principal if any, and
`aud`, all from the pinned manifest and the checked response. It then signs an
`aweb.owner-act/1` with that `act`, `aud` and `subject`, the team's
`team_id` and current controller key, and an `expires_at` no later than the
earlier of ten minutes after `issued_at` and the response's `expires_at`.

A custodial deployment that signs for the owner applies the same checks and
shows the same facts behind its step-up ([owner-act.md](owner-act.md#who-signs)).

## Delivery

`POST <owner_acts.origin>/.well-known/aweb-owner-act` with
`Content-Type: application/json` and no team-auth, cookie or session. The act
is the only authority.

Body, a JSON object with exactly these fields:

- `signing`: the act's signing bytes, in standard base64 with padding;
- `signature`: as owner-act/1 spells it;
- `contact`: the contact itself, required for designate and recover and
  refused for revoke. The app sends the enrolment link there, after the
  transaction commits.

The app reads `act`, `installation_id` and `role` from the signing bytes only
as lookup keys. It finds its own pending row or current holder, admits the
installation, and verifies the act with that row as the expected subject,
consuming the nonce in the transaction that applies the effect
([Verification](owner-act.md#verification)). For designate and recover it also
requires the SHA-256 of `contact` to equal the row's contact hash.

The anonymous route makes its local checks before it reads the registry:

- the body;
- the act's parse, fields and subject;
- the team, audience, vocabulary and lifetime;
- the nonce;
- the pending row or holder, and the contact hash.

Only an act that passes them costs a read of the team's current controller key
and a signature check. Every fault is the same `owner_required`, so this
order changes no response.

Response `200`:

```json
{"act": "app-role.designate", "role": "logs.reader.00112233445566778899aabbccddeeff", "effective_at": "2026-11-07T12:01:00Z"}
```

`effective_at` is when the effect holds; a recovery under a cooling-off period
names its end.

| Status | `detail` | When |
| --- | --- | --- |
| 415 | `json_required` | The content type is not `application/json`. |
| 400 | `request_invalid` | The body is not exactly the fields above, `signing` is not base64, or the bytes yield no act, installation id and role to look up. |
| 403 | `owner_required` | Every other fault of the act or its row: any owner-act verification code, no pending row or holder, a row of another installation, a contact that does not match, a reused nonce. |
| as given | the installation's code | The installation is not admitted. |
| 503 | `release_context_unavailable`, or the verifier's code | The governance event cannot be recorded, or the team's registry cannot be read. Nothing took effect. |
| 429 | `owner_act_rate_limited` | The client's delivery budget is spent; the response carries `Retry-After`. The budget is keyed on the client address that `aweb_naapp.console.ClientIdentity` resolves: the peer, or the entry the deployment's trusted proxy header names. |

The route is anonymous, so every act and row fault is one refusal, and no
response echoes the request. An anonymous caller learns nothing about which
rows or holders exist. A failed effect rolls back the nonce, so the owner may
deliver the same act again until it expires.

## Why a member gains nothing from prepare

A member who holds the prepare scope can create pending rows and read a
current holder's token, and nothing more:

- a pending row is not a role, a session or an enrolment; only an owner act
  naming that row, signed by the current controller key, takes effect, and the
  member cannot sign one;
- the owner's client prepares its own row from the contact the owner typed and
  checks the returned hash, so a member's row for another contact is never
  what the owner signs;
- rows are keyed by token and contact hash, so a member's row never displaces
  the owner's;
- rows expire, and prepare is rate-limited per member.

**secrets.** secrets' owner role declares the scope `secrets:owner-act` on its
prepare tool, and no other tool requires it. It is separate from
`secrets:admin`, so an installation can grant it to the owner's member
identity without granting containment or change proposals. A holder of
`secrets:owner-act` gains no owner, approver or session; each owner
designation and recovery still needs the controller key, and recovery keeps
its 72-hour cooling-off period. **logs.** logs' reader role declares
`logs.readers`, the scope that already governs reader slots.

## Rollout of manifest version 3

- Only an app that declares `owner_acts` serves version 3, and only its
  installations are re-pinned. An app that declares none serves no version 3,
  and its installations are untouched.
- An app that declares `owner_acts` serves a catalog listing its version 2
  and version 3 variants ([Variant discovery](app-manifest.md#variant-discovery)).
- Released clients, which support version 2 at most, keep selecting version 2,
  unchanged. Only a client that supports version 3 selects it.
- The server pins each installation's manifest version. An installation
  pinned to version 2 has no `owner_acts`. A client refuses an app owner act
  for it with `owner_acts_undeclared`, and the owner re-pins.
- Re-pinning to version 3 is an update. It keeps the installation id and starts
  the installation's next generation, so every hook binding of the installation is superseded and
  the owner re-activates each one. Role holders, enrolments and app data are
  keyed by installation id and are kept.
- Between the re-pin and the re-activation, an app whose effects require an
  active audit binding refuses them. secrets refuses every secret use until
  both of its hook bindings are re-activated. The owner re-pins and
  re-activates in one sitting.

## Work this contract creates

Filed after Juan rules on the design. Each item is one reviewed change.

- **Go manifest interpreter** (`cli/go/internal/appmanifest`): version 3 and
  `owner_acts`, against the version 3 vectors.
- **`aweb_naapp`**: version 3 in `aweb_naapp.manifest`; a generic owner-act
  delivery router mounted on the human origin, which makes its local checks
  before the registry read and keys its delivery limit on the
  `ClientIdentity` client address; a generic prepare router with pending
  rows and the per-member rate limit.
  `split_origins` accepts two origins on one hostname with different ports, so
  the runtime refuses an `owner_acts.origin` that shares `app.origin`'s
  hostname.
- **Server** (`server/src/aweb`): version 3 in `SUPPORTED_MANIFEST_VERSIONS`,
  with install and re-pin at a pinned version 3.
- **`aw`** (C3, aweb-acgh.16.18): `aw app role designate|revoke` and
  `aw app credential recover` on this contract, through manifest version 3.
- **secrets**: declare `owner_acts` (role `secrets.owner`, principal
  `required`, all three acts), the prepare tool with `secrets:owner-act`, and
  the pending rows. Move designate and recover from
  `POST /installations/{id}/owner-acts` to the delivery route, and add
  `app-role.revoke` for owners, which secrets has no route for.
- **logs**: declare `owner_acts` (role `logs.reader`, principal `refused`, all
  three acts), and declare the prepare tool with `logs.readers`; the
  `/v1/reader-slots` route has no declared tool, so the runtime never admits a
  call to it. Move designation and revocation from `/readers/designations`
  and `/readers/revocations` to the delivery route, and add
  `app-credential.recover`, which logs has no route for.
- **Hosted (servers team, through the secrets coordinator)**: version 3 in the
  hosted gateway's manifest handling; re-pinning installed apps to version 3,
  with the owner's re-activation of hook bindings; and the custodial signing
  path for app owner acts (step-up, prepare, the checks above, delivery).
