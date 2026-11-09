# Owner-designated roles held by a team's humans

Status: **proposed, awaiting Juan's ruling** (aweb-acgh.16.38, for the LF demo
epic aweb-acwd). This is a change to the specified
[owner-act delivery contract](../owner-act-delivery.md). With it, the holder of
an owner-designated role (a secrets owner, a logs reader) is an existing human
member of the team, named by its principal. That replaces a contact enrolled
into a naapp-local account. The contract text changes only after the ruling.
The [native human confirmation profile](native-human-confirmation.md)
(aweb-acwd.4) is how the holder then uses the role.

Requirement: Bookshelf `kb/concepts/customer-agent-servers.md` at `5c83ed85`
(lines 21-24, and gap G-B at line 76). There are no naapp member accounts, and
the same verified human identity serves every naapp.

## Summary for Juan

| Ruling | Recommended | Main tradeoff |
| --- | --- | --- |
| H1. Added acts or a changed subject | Three acts added to `aweb.owner-act/1`, which is additive | The contact acts stay in the vocabulary, unused, until a separate removal. |
| H2. Who may hold a role | A current team member of human kind, checked at designation and on every use | An auditor who is not a team member cannot be a logs reader, and each use needs the registry. |
| H3. Lockout and recovery notices | The `post-governance-hook` event only, with no email | A human role has no contact, so it has no out-of-band notice. The 72-hour freeze and the hook event stay. |
| H4. Whose credential the act binds | The controller act binds it. When the owner is not the holder, the two clients compare a fingerprint | Trust on first use rests on that comparison. |

## Reused unchanged

- **The owner act** ([owner-act.md](../owner-act.md#verification)): the
  envelope, the current controller key read fresh from the registry, the
  verification order, the ten-minute lifetime and single-use nonces. Only the
  controller key designates; an install, admin or member signature is refused
  with `owner_required`. Nothing here adds or relaxes a BYOT authority check.
- **The human origin as audience** ([Declaration](../owner-act-delivery.md#declaration)):
  `owner_acts.origin` in manifest version 3. It is the act's `aud` and where
  the act is delivered, and the [rollout and re-pin](../owner-act-delivery.md#rollout-of-manifest-version-3)
  is kept.
- **The delivery route** ([Delivery](../owner-act-delivery.md#delivery)):
  `POST <owner_acts.origin>/.well-known/aweb-owner-act`, which is anonymous,
  with its three stages, statuses and delivery limit.
- **B3's approver record and its proof.** The holder is an app-local approver
  row linked to the member principal. secrets already derives an owner's scope
  from the installation, the team and that principal
  (`naapp/secrets/src/aweb_secrets/owners.py:43`). Every login and approval is
  still a user-verified WebAuthn assertion, retained as
  `aweb.passkey-evidence/1`. Holding the principal's team-auth key is still not
  enough to approve anything (`docs/design/secrets.md:585`). The recovery
  cooling-off and last-owner protection stay (secrets §10.2).

## What changes

### Three acts

These are additive within `aweb.owner-act/1` ([Versioning](../owner-act.md#acts-and-subjects)).
Every naapp's vocabulary adds them:

- **`human-role.designate`**: `app_id`, `installation_id`, `role`, `principal`
  and `credential_sha256`. It makes `principal` the holder of `role`, using
  that credential.
- **`human-credential.replace`**: the same fields. It replaces the current
  holder's credential after the cooling-off period, as
  `app-credential.recover` does.
- **`human-role.revoke`**: `app_id`, `installation_id`, `role` and
  `principal`.

The fields:

- `role` is the declared role name (`secrets.owner`, `logs.reader`), not a
  token.
- `principal` is the member's `did:aw`. A human always has one
  (`docs/id-certificates.md:71-72`).
- `credential_sha256` is the lowercase hex SHA-256 of
  `aweb.human-credential/1\n` followed by the canonical JSON
  `{"credential_id": <base64url>, "public_key": <base64url>}`. The values are
  the authenticator's credential id and its COSE public key bytes, each
  unpadded base64url.

`app-role.designate`, `app-credential.recover` and `app-role.revoke` keep
their meaning. An app that declares a role with the human-role acts accepts no
contact act for that role (H1).

### Declaration

An `owner_acts.roles` entry keeps `name`, `label`, `description` and `acts`.
Its `acts` is a nonempty subset of the three human-role acts. It drops
`principal`, because every human role binds a principal, and `prepare_tool`,
for the reason in the next section.

### No prepare, no pending rows, no role tokens

Prepare had two jobs: to carry a token the app chose without deriving it from
the contact, and to commit the contact before the owner signed. With a
principal, neither applies. A principal is public and names the holder, so the
app keys the holder by (installation, role, principal), and the act names the
credential itself. Removing prepare also removes:

- the prepare tool and its five fields;
- the pending rows and their lifetimes;
- `secrets:owner-act` and the per-member prepare limit;
- the client's `prepare_mismatch` checks;
- the section [Why a member gains nothing from prepare](../owner-act-delivery.md#why-a-member-gains-nothing-from-prepare).

A member takes no part in designation.

### Delivery body and stage 3

The body is `signing`, `signature` and, for designate and replace,
`credential`: `{"credential_id", "public_key"}` in the same encoding. It is
refused for revoke. It carries no `contact`, and the app sends no enrolment link.

Stages 1 and 2 are unchanged. For an authenticated act, stage 3 checks:

- the installation, admitted, whose team is the act's `team_id`;
- the nonce, consumed in the effect's transaction;
- for designate and replace only: `principal` holds a current certificate of
  that team, and its own registered ID kind is `human` (H2). The kind is the subject's own, never the
  kind of its nearest human ancestor or a label. A registry that cannot answer
  refuses with `503 principal_status_unavailable`. Nothing takes effect, and
  the outcome depends only on the act. `aweb_naapp` lacks this wiring:
  its team-auth verifier checks no kind. It reuses the public verifier
  `observe_identity_kind` (`server/src/aweb/human_kind.py:38`), together with
  the naapp's current team-certificate check and an exact match of key and
  ID;
- for designate and replace: the SHA-256 of `credential` against
  `credential_sha256`, and a COSE key with no private parameters, by B3's
  existing retention check (`naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py:395-408`);
- designate requires that (role, principal) has no current holding; replace
  and revoke require that it has one.

Revoke checks no membership or kind. It targets the stored holding of
(installation, role, principal), so a controller act can retire a holder whose
membership has already ended. Its authority is the controller key, verified in
stage 2, and it never reads the holder's identity status, so a registry that
cannot answer about the holder does not delay it.

A principal that is not a current member of the team refuses with
`403 principal_not_member`, and one that is not of human kind with
`403 principal_not_human`. The principal is public, so these codes reveal
nothing, and they tell the owner what to fix. Every other fault of the act or
its holding is `403 owner_required`. Only `503 principal_status_unavailable`
is retryable; the 403s are final for that act. The kind and certificate
checks reuse the 60-second team-facts cache where it applies.

**Effects:**

- **Designate** creates the approver row linked to `principal`, with the
  credential stored at sign count 0 and in effect at once.
- **Replace** retires the current credential at once and puts the replacement
  in effect at the end of the cooling-off. Until then, the holder's approvals and the widening changes
  it gates are frozen.
- **Revoke** ends the holding.

Each emits `post-governance-hook` with `authority: owner_act`.

### Use

A holder logs in and approves only through the
[native profile](native-human-confirmation.md), with the bound credential.
Each login and each approval re-checks that `principal` is still a current
human member. An unknown answer refuses, and a revoked membership ends the
holder's authority. No browser enrolment exists for a human role. The browser
ceremony stays for contact roles.

### What the owner's client shows and signs

The client shows:

- the app (id and origin);
- the role (app and `label`);
- the act;
- the principal, with its address and kind as the registry reports them;
- the credential's fingerprint: the first 16 hex characters of
  `credential_sha256`, in groups of four.

It then signs. When the owner is the holder, one client creates the credential
and signs the act in one sitting. When the holder is someone else, the
holder's client exports the public credential, and the owner signs only after
the two clients show the same fingerprint (H4). That comparison helps only
under two conditions:

- the holder's client read the credential from the intended authenticator;
- the fingerprint travels over a channel that the holder's custodian does not
  control, such as in person or a call.

aweb mail, a notice, or a second key under the same custodian is not such a
channel. Two `did:aw` values do not prove two people. A custodial deployment
that signs for the owner shows the same facts behind its step-up.

## Why this keeps the boundaries

- **Who authorizes the binding.** Only the current controller key binds a
  credential to a holder. That is the trust root the contact link stood in
  for. The holder's own key never authorizes a binding, so an agent or a
  custodian that holds the human key cannot enrol a substitute credential.
- **What the gesture proves.** B3's verifier and retained evidence prove a
  user-verified assertion by the bound credential. No attestation is claimed.
- **What membership does.** Membership is required but never sufficient: the
  holding comes only from the owner act, and resource grants stay separate.

## Work this changes

After the ruling:

- the contract text in [owner-act.md](../owner-act.md#acts-and-subjects),
  [owner-act-delivery.md](../owner-act-delivery.md) and
  [app-manifest.md](../app-manifest.md#manifest-version-3);
- the vector, generator and test under `naapp-lib/tests/hooks/`, re-frozen by
  the same review;
- the follow-ups filed for 16.38 (16.40 to 16.45): their prepare and contact
  work drops, and the human-role acts and the native profile replace it;
- C3's `aw app role designate|revoke` and `aw app credential replace`, naming
  `--principal`.
