# Owner-act delivery for app acts

Status: **specified, not shipped**. Owner: the aweb OSS hooks lane
(aweb-acgh.16.38, with the [human-role holders](design/human-role-holders.md)
design that Juan ruled). This document is the source of truth for how a client
delivers an app's human-role owner act (`human-role.designate`,
`human-role.revoke` and `human-credential.replace`, defined in
[the owner-act contract](owner-act.md)) to the naapp that verifies it, with no
per-app code in the client. Its vector is
`docs/vectors/owner-act-delivery-v1.json`.

The owner-act contract fixes the signed artifact and its verification. This
contract adds what that one leaves to the transport:

- where the app's human origin and its owner-designated roles are declared, and
  so what `aud` is;
- how the inputs that are not in the act (the credential and the notice
  contact) travel and are checked;
- the one delivery route, and its refusals.

## Design choices

| Choice | Taken | Rejected, and why |
| --- | --- | --- |
| Where the human origin and the owner-designated roles are declared | `owner_acts` in [manifest version 3](app-manifest.md#manifest-version-3), served as a catalog variant beside version 2 | A field in version 2 breaks every released `aw` from 1.36.46 to 1.36.56, which refuse unknown fields. A separate, unpinned well-known document lets the human origin change after install without review. |
| Who holds an owner-designated role | A current human member of the team, named by its principal, with a credential the act binds (H1, H2, H4) | A contact enrolled into a naapp-local account gives each naapp its own account for the same person. Prepare, pending rows and app-issued role tokens existed only to name such a holder before it existed. |
| How lockout and recovery notices reach the holder | A notice-only contact, for the roles that declare one (H3) | An enrolment contact doubles as a credential channel; a notice contact never carries a link or a key. |

The pinned manifest is then the only reviewed source of what an owner signs
for and where the act goes, as it already is for hook-binding acts.

## The model

- **Authority.** Only the owner act is authority. It is signed by the team's
  current controller key ([Who signs](owner-act.md#who-signs)). Nothing in
  this contract adds or relaxes an owner-act check.
- **The holder is a team member.** A role holder is the principal the act
  names, a current member of the team whose own registered ID kind is `human`.
  Membership is required, never sufficient: the holding comes only from the act.
- **The act binds the credential.** Designate and replace name the holder's
  credential by its hash. The holder's own key never binds a credential, and a
  [`credential` handoff](design/human-confirmation-from-aw.md#the-handoff)
  that produces one grants nothing by itself.
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
        "acts": ["human-credential.replace", "human-role.designate", "human-role.revoke"],
        "notice_contact": false
      }
    ]
  }
}
```

- `origin` is in owner-act/1's audience grammar: `https://`, a lowercase
  host, an optional port, and no path, trailing slash, query, fragment or
  userinfo. Its hostname differs from `app.origin`'s. It is the `aud` of every
  act for this app, compared byte for byte, so a declaration that no signer
  could put in `aud` is refused. A port or a trailing dot does not make two
  hostnames differ.
- `roles` has 1 to 16 entries, unique by `name`.
  - `name` follows the designatable role grammar (dot-separated lowercase
    segments, at least two, `[a-z0-9][a-z0-9_-]*` each), begins with a letter,
    and is at most 64 bytes, so it fits owner-act/1's `role` grammar. It is the
    act's `role` and the `post-governance-hook` `role`.
  - `label` and the optional `description` follow the rules of the version 2
    `roles` field: 1 to 128 and 1 to 512 characters, with no C0, C1 or bidi
    control. Every surface that shows the role shows the pair of app and name.
  - `acts` is a nonempty set of the three human-role acts, ascending by code
    point with no repeat.
  - `notice_contact` is `true` when designate and replace name a notice
    contact for the holder, and `false` when they name none.
- `session_actions`, optional, declares the human-origin actions `aw` drives
  in a holder's session ([Session actions](design/human-confirmation-from-aw.md#session-actions-what-aw-drives)).
- `owner_acts` and the version 2 `roles` field are separate. The version 2
  field declares roles a team admin designates; `owner_acts` declares roles
  only an owner act designates.

An app accepts no contact act (`app-role.designate`, `app-role.revoke`,
`app-credential.recover`) on this route.

## The credential

A credential is `{"credential_id", "public_key", "rp_id"}`:

- `credential_id` is the authenticator's credential id and `public_key` its
  COSE public key bytes, each in unpadded base64url;
- `rp_id` is the hostname of `owner_acts.origin` for a browser passkey, the
  default, or exactly `aweb:` for the
  [optional security key](design/human-confirmation-from-aw.md#optional-a-security-key-from-the-terminal).

`credential_sha256` is the lowercase hex SHA-256 of `aweb.human-credential/1`
and a newline, followed by the credential's canonical JSON under owner-act/1's
rules (sorted keys, no insignificant whitespace, printable ASCII). The
credential's **fingerprint** is the first 16 hex characters of
`credential_sha256`, in four groups of four separated by spaces.

`notice_contact_sha256` is the lowercase hex SHA-256 of the UTF-8 notice
contact, B3's `contact_sha256`.

## What the client checks, shows and signs

The client builds the subject itself, from the pinned manifest and the
registry; no app call precedes the act. Before it shows the owner anything, it
refuses to sign unless all of these hold:

- the role is declared in the pinned manifest's `owner_acts`, and the act is in
  its `acts`;
- the installation is the one the client resolved for this app and team;
- for designate and replace, the registry reports the principal as a current
  member of the team whose own ID kind is `human`;
- for designate and replace, the credential's `rp_id` is the hostname of
  `owner_acts.origin`, or `aweb:` when the owner chose the optional security
  key, and a notice contact is given exactly when the role declares one.

The client shows:

- the app (id and origin);
- the role, as the pair of app and `label`;
- the act;
- the principal, with its address and kind as the registry reports them;
- for designate and replace, the credential's kind (a browser passkey at the
  origin's hostname, or a security key) and its fingerprint, and the notice
  contact when the role declares one;
- `aud`.

It then signs an `aweb.owner-act/1` with that `act`, `aud` and subject, the
team's `team_id` and current controller key, and an `expires_at` at most ten
minutes after `issued_at`. When the owner is not the holder, the owner signs
only after the holder's client and the owner's client show the same
fingerprint ([What the owner's client shows and signs](design/human-role-holders.md#what-the-owners-client-shows-and-signs)).

A custodial deployment that signs for the owner applies the same checks and
shows the same facts behind its step-up ([owner-act.md](owner-act.md#who-signs)).

## Delivery

`POST <owner_acts.origin>/.well-known/aweb-owner-act` with
`Content-Type: application/json` and no team-auth, cookie or session. The act
is the only authority.

Body, a JSON object with exactly these fields:

- `signing`: the act's signing bytes, in standard base64 with padding;
- `signature`: as owner-act/1 spells it;
- `credential`: the credential object above, with exactly its three fields,
  required for designate and replace and refused otherwise;
- `notice_contact`: the notice contact, a nonempty string, required for
  designate and replace of a role that declares one and refused otherwise.

The route authenticates the act before any check that depends on the app's
state, so no refusal before authentication can tell an anonymous caller
whether a holding or installation exists. It checks in three stages:

1. **Stateless,** in this order: the body's fields and encodings; the act's
   parse, fields and subject shape; its audience against `owner_acts.origin`;
   its role, declared in `owner_acts`, and its act, in that role's `acts`;
   then whether the body carries `credential` and `notice_contact` exactly as
   the act and the role's `notice_contact` require; then its lifetime and
   expiry. These need no read.
2. **Authentication:** the current controller key of the act's `team_id`,
   read from the registry (cached at most 60 seconds), and the signature under
   it. A registry that cannot be read refuses with `503`
   `team_key_unavailable`. That outcome depends only on the `team_id` the
   caller chose, never on the app's rows.
3. **State, for an authenticated act only,** in this order:
   1. the installation that `installation_id` names, admitted, whose team is
      the act's `team_id`;
   2. for designate and replace, the credential: a COSE key with no private
      parameters, by B3's retention check, and an `rp_id` that is the hostname
      of the act's `aud` or, where the app enables the optional security key,
      exactly `aweb:`;
   3. the holding of (installation, role, principal): designate requires that
      none is current, and replace and revoke require that one is;
   4. for designate and replace, the principal: it holds a current certificate
      of that team, and its own registered ID kind is `human`. The kind is the
      subject's own, never the kind of its nearest human ancestor or a label.
      These reads reuse the 60-second team-facts cache where it applies. The
      certificate is the one the holder's `credential` handoff retained
      ([membership evidence](design/human-confirmation-from-aw.md#membership-evidence));
   5. in the transaction that applies the effect, the act against the expected
      subject, and its nonce, consumed. The expected subject is the app's own
      `app_id`, the installation, the act's `role` and `principal` and, for
      designate and replace, the SHA-256 of the body's `credential` and of its
      `notice_contact` when the role declares one. The holding is re-read under
      the transaction's lock, and the act's `expires_at` is checked again
      against the clock read after that lock: an act that expired while
      stage 3 waited is refused and the transaction rolls back.

Revoke checks no membership or kind. It targets the stored holding, so a
controller act can retire a holder whose membership has already ended, and a
registry that cannot answer about the holder does not delay it.

The app reads `act`, `installation_id`, `role` and `principal` from the
signing bytes only as lookup keys for stage 3. An act with a valid shape costs
one registry read for its team, which the cache and the delivery limit bound.
Each check of the act is one of owner-act/1's ([Verification](owner-act.md#verification)).
Only the stage at which it runs changes, and every fault of stages 1 and 2 is
`owner_required` or the `503` above, so the order is the only thing a caller
observes.

Response `200`:

```json
{"act": "human-role.designate", "role": "logs.reader", "principal": "did:aw:2Zf4Lq8m3VYb9nKc5RjTs7Hd", "effective_at": "2026-11-07T12:01:00Z"}
```

`effective_at` is when the effect holds; a replacement names the end of its
cooling-off period.

| Status | `detail` | When |
| --- | --- | --- |
| 415 | `json_required` | The content type is not `application/json`. |
| 400 | `request_invalid` | The body has a field outside the four above, `signing` is not base64, a credential field is not in its encoding, the bytes yield no act, installation id and role to look up, or, for a declared role and act, the body does not carry `credential` and `notice_contact` exactly as they require. |
| 403 | `owner_required` | Every other fault of the act, its credential or its holding: any owner-act verification code, an undeclared role or act, a credential refused in stage 3, a holding in the wrong state, a credential or notice contact that does not match the act, a reused nonce. |
| 503 | `team_key_unavailable` | Stage 2 cannot read the team's current key. Nothing took effect. |
| as given | the installation's code | An authenticated act names an installation that is not admitted. |
| 403 | `principal_not_member` | Designate or replace names a principal that holds no current certificate of the team. |
| 403 | `principal_not_human` | Designate or replace names a principal whose own registered ID kind is not `human`. |
| 503 | `principal_status_unavailable` | Designate or replace, and the registry cannot answer for the principal's membership or kind. Nothing took effect. |
| 503 | `release_context_unavailable` | The governance event cannot be recorded. Nothing took effect. |
| 429 | `owner_act_rate_limited` | The client's delivery budget is spent; the response carries `Retry-After`. The budget is keyed on the client address that `aweb_naapp.console.ClientIdentity` resolves: the peer, or the entry the deployment's trusted proxy header names. |

The route is anonymous, so every act and holding fault is one refusal, and no
response echoes the request. Only the controller key's holder reaches a
state-dependent outcome, so an anonymous caller learns nothing about which
holdings or installations exist. The principal is public, so
`principal_not_member` and `principal_not_human` reveal nothing, and they tell
the owner what to fix. The two `503`s are retryable; the `403`s are final for
that act. A failed effect rolls back the nonce, so the owner may deliver the
same act again until it expires.

**Effects:**

- **Designate** creates the holding of (installation, role, principal): B3's
  approver row linked to the principal, with the credential and its `rp_id`
  stored at sign count 0 and in effect at once, and the notice contact. The
  holder changes that contact later through B3's contact change, under its
  passkey.
- **Replace** retires the current credential at once and puts the replacement
  in effect at the end of the cooling-off period. Until then, the holder's
  approvals and the widening changes they gate are frozen.
- **Revoke** ends the holding.

Each emits `post-governance-hook` with `authority: owner_act`, and the app
sends no enrolment link.

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
  the owner re-activates each one. Role holders and app data are keyed by
  installation id and are kept.
- Between the re-pin and the re-activation, an app whose effects require an
  active audit binding refuses them. secrets refuses every secret use until
  both of its hook bindings are re-activated. The owner re-pins and
  re-activates in one sitting.

## Work this contract creates

Filed with the 16.38 follow-ups and the
[human-role holders follow-ups](design/human-role-holders.md#work-this-changes).
Each item is one reviewed change.

- **Go manifest interpreter** (`cli/go/internal/appmanifest`): version 3 and
  `owner_acts`, against the version 3 vectors.
- **`aweb_naapp`**: version 3 in `aweb_naapp.manifest`; a generic owner-act
  delivery router mounted on the human origin, which runs the three stages in
  order, checks the principal's membership and kind with the public verifier
  `observe_identity_kind` and the naapp's current team-certificate check, and
  keys its delivery limit on the `ClientIdentity` client address.
  `split_origins` accepts two origins on one hostname with different ports, so
  the runtime refuses an `owner_acts.origin` that shares `app.origin`'s
  hostname.
- **Server** (`server/src/aweb`): version 3 in `SUPPORTED_MANIFEST_VERSIONS`,
  with install and re-pin at a pinned version 3.
- **`aw`** (C3, aweb-acgh.16.18): `aw app role designate|revoke` and
  `aw app credential replace` on this contract, through manifest version 3,
  naming `--principal` and, where the role declares one, the notice contact.
- **secrets**: declare `owner_acts` for its owner-designated roles, with
  `notice_contact` for owners and issuers (D9a), and all three acts. Move
  designation from `POST /installations/{id}/owner-acts` to the delivery route.
- **logs**: declare `owner_acts` (role `logs.reader`, no notice contact, all
  three acts). Move designation and revocation from `/readers/designations`
  and `/readers/revocations` to the delivery route.
- **Hosted (servers team, through the secrets coordinator)**: version 3 in the
  hosted gateway's manifest handling; re-pinning installed apps to version 3,
  with the owner's re-activation of hook bindings; and the custodial signing
  path for app owner acts (step-up, the checks above, delivery).
