# Owner act: `aweb.owner-act/1`

Status: **specified experimental public contract, not yet shipped**. Owner: the
aweb OSS hooks lane (aweb-acgh.16). This document is the source of truth for the
signed artifact by which a team's owner authorizes a governance act that no
admin, member or agent can perform. Its vector is
`docs/vectors/owner-act-v1.json`, and its Go authority is `cli/go/awid/owneract.go`,
which regenerates the vector byte for byte. The design and its rationale are
in [the audit substrate design](design/audit-substrate.md), §2 and §A3.

This is an identity-path change. Juan approved `aweb.owner-act/1` explicitly,
with the ruling below on who may sign one.

## Who signs

An owner act is valid only from the team's **controller authority**, exercised
by the organization owner:

- For a team whose controller key the owner holds (BYOT), the owner signs
  locally with that key.
- For a team whose controller key a custodial deployment holds, the deployment
  signs only for the **organization owner** (never an organization admin or any
  other role), and only after the owner's **fresh interactive step-up**, such
  as a passkey or re-authentication. It never signs with a stored credential, an
  API key or an MCP token. Its signer is a narrow provisioning signer, not
  controller-key material loaded into every request process.

**Disclosure.** A custodian of the controller key can mint any owner act:
activate or revoke hook targets, designate itself a reader, set retention or
erase. For a team whose controller key is held by a hosted operator, the audit
record therefore protects against agents and other apps, **not against that
operator**. Only owner-held controller custody, together with a self-hosted
logs installation, removes the operator from the trust base.

A working credential, a role label, a team certificate or a domain string is
never owner authority.

**What a verifier proves, and what it cannot.** A verifier proves that an act
was signed by the team's current controller key, for that verifier, within its
lifetime, naming the expected subject. It cannot tell who held the key.
Signing only for the organization owner, only after a fresh step-up, and only
through a narrow signer are obligations of the deployment that signs, not
checks a verifier can make. For a custodial deployment they are acceptance
criteria of its signing path:

- the owner's step-up is at most five minutes old when the act is signed;
- the step-up challenge is bound to the act, as the SHA-256 of the owner act's
  signing bytes, so one gesture signs exactly one act;
- signing several acts behind one gesture is refused, so no queue of pending
  items can be signed by a single owner tap.

## The artifact

```json
{
  "v": 1,
  "type": "aweb.owner-act",
  "act": "hook-binding.activate",
  "team_id": "demo:example.com",
  "aud": "https://aweb.example.com",
  "team_key_did": "did:key:z6Mk...",
  "subject": {"binding_id": "...", "installation_id": "...", "generation": 2, "...": "..."},
  "issued_at": "2026-10-20T12:00:00Z",
  "expires_at": "2026-10-20T12:05:00Z",
  "nonce": "0101...01"
}
```

- **Signing bytes** are the ASCII prefix `aweb.owner-act/1` and a newline,
  followed by the act's canonical JSON, under the same strict rules as hook
  events: sorted keys, no insignificant whitespace, printable ASCII strings with
  only `"` and `\` escaped, safe-range integers, no floats and no `null`. The
  prefix is unique to this artifact, so no team certificate or controller
  envelope verifies as an owner act, and no owner act as one of them.
- **The signature** is a detached Ed25519 signature by `team_key_did`, the
  team's current controller key, in standard base64 without padding.
- `aud` is the origin of the one verifier the act is for.
- `issued_at` and `expires_at` are UTC to the second. An act lives at most ten
  minutes.
- `nonce` is 16 random bytes as 32 lowercase hex characters. Each verifier
  accepts it once.

## Acts and subjects

Each verifier accepts only its own closed vocabulary. A valid act for another
audience or vocabulary is refused.

| Verifier | Acts |
| --- | --- |
| The coordination server | `hook-binding.activate`, `hook-binding.revoke` |
| Every naapp | `app-role.designate`, `app-role.revoke`, `app-credential.recover` |
| logs, in addition | `logs.retention.set`, `logs.erase`, `logs.legal-hold.set`, `logs.legal-hold.release` |

Subjects are flat objects. A field marked "when" is required in that case and
refused otherwise.

- **`hook-binding.*`**:
  - always: `binding_id`, `installation_id`, `generation`, `app_id`, `origin`,
    `digest` (the `sha256:` manifest digest the owner's client fetched and
    hashed), `kind`, `catalog_id`, `catalog_version`, `hook`;
  - when `kind` is `registration`: the resolved `tool`, `method`, raw `path`
    and the app `scopes`;
  - when `kind` is `production`: `reads`, the tools whose reads fire
    `post-manifest-command-hook`, possibly empty.
- **`app-role.designate` and `app-credential.recover`**: `app_id`,
  `installation_id`, `role` and `contact_sha256`. They name a role holder who
  does not exist yet, so they carry no `subject_ref`, and one is refused: the
  app mints the subject when it enrols the holder. `contact_sha256` is the
  lowercase hex SHA-256 of the UTF-8 contact the enrolment link goes to. The
  act commits to the contact without carrying it, and the app refuses to enrol
  any other contact under it. The first holder of an owner-designated role,
  such as a logs reader or a secrets owner, is designated this way and never by
  install or admin authority; recovery after a lockout uses
  `app-credential.recover`.
- **`app-role.revoke`**: `app_id`, `installation_id`, `role` and
  `subject_ref`, the existing holder.

`role` is the app's role scope, a token such as `logs.reader`,
`secrets.owner` or `secrets.approver.<policy>`. It is the same value the
`post-governance-hook` `role` field carries.
- **`logs.retention.set`**: `app_id`, `installation_id`, `event_class` (`all`
  or one hook) and `retention` (`keep`, or `days` with `retention_days` from 1
  to 36500).
- **`logs.erase`**: `app_id`, `installation_id`, `reason_code` and
  `erase_scope`. `actor` erases with `actor_ref`; `range` erases with
  `chain_epoch`, `team_seq_first` and `team_seq_last`.
- **`logs.legal-hold.set`**: `app_id`, `installation_id`, `hold_id`,
  `reason_code` and `hold_scope`, where `all` holds everything and `actor` holds
  `actor_ref`.
- **`logs.legal-hold.release`**: `app_id`, `installation_id` and `hold_id`.

**Versioning.** The act name is signed, so adding a new act, with a new name
and its own subject, is additive within `aweb.owner-act/1`. Changing an
existing act's subject, or what it means, needs `aweb.owner-act/2`.

## Verification

A verifier holds facts of its own that it never takes from the act:

- its team;
- the team's **current** controller key, read fresh from the team's registry,
  cached at most 60 seconds, so a rotated-out key stops working promptly;
- its own audience and vocabulary;
- its clock;
- the stored row the act must name: every owner act's effect is on a known row,
  such as the pending binding or the requested enrolment. An app or logs
  verifier's row carries its own `app_id` and `installation_id`, so an act for
  another app or installation never matches;
- the nonces it has already consumed.

Every one of these is required. A verifier missing any of them refuses
(`verifier_misconfigured`). It then checks, in this order, and reports the
first fault:

1. the prefix (`wrong_prefix`);
2. a strict parse (`duplicate_key`, `float_value`, `null_value`,
   `string_not_ascii`, `too_deep`, `invalid_json`) and canonical bytes
   (`not_canonical`);
3. the field names (`unknown_field`, `missing_field`); `v` and `type`
   (`invalid_value`); a known act (`unknown_act`); the field formats (`aud`,
   `expires_at`, `issued_at`, `nonce`, `team_id`, `team_key_did`), real times
   in their canonical spelling, and `expires_at` after `issued_at`
   (`invalid_value`); then the subject, including `team_seq_first` at or before
   `team_seq_last` for `logs.erase`;
4. the team (`team_mismatch`);
5. the audience (`audience_mismatch`);
6. the act is in the verifier's vocabulary (`act_not_allowed`);
7. a lifetime of at most ten minutes (`lifetime_too_long`), an `issued_at` at
   most 60 seconds ahead (`not_yet_valid`), and not expired (`expired`);
8. `team_key_did` is the current controller key (`owner_required`). An admin's
   or member's key, or a rotated-out team key, is refused here;
9. the signature is spelled exactly (86 standard base64 characters, no padding,
   zero trailing bits; `signature_encoding`) and verifies under that key
   (`bad_signature`);
10. the nonce is unused (`nonce_reused`);
11. the subject is exactly the stored row (`subject_mismatch`), compared as
    canonical bytes.

**Single use.** A read that finds the nonce unused does not by itself stop two
concurrent requests carrying the same act, so the verifier serializes them:

- it inserts the nonce, with the SHA-256 of the act's signing bytes, under a
  unique constraint on (verifier scope, team, nonce), in the same transaction
  as the act's effect;
- a conflict rolls the effect back and refuses with `nonce_reused`, so one
  `app-credential.recover` can never enrol two credentials;
- a failed effect rolls the insert back too, so the owner may retry the same
  act;
- nonce rows are kept at least until the act's `expires_at` plus the 60-second
  allowance, after which the act could not verify anyway. Every owner act produces an audit
event: core emits `post-mutation-hook` `hook_binding.activated` or
`hook_binding.revoked`, and a naapp emits `post-governance-hook` with
`authority: owner_act` and `owner_act_sha256`.
