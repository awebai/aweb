# Owner-designated roles held by a team's humans

Status: **decided** (aweb-acgh.16.38, for the LF demo epic aweb-acwd). Juan
ruled H1 to H4 and the browser default for use. This is a change to the specified
[owner-act delivery contract](../owner-act-delivery.md). With it, the holder of
an owner-designated role (a secrets owner, a logs reader) is an existing human
member of the team, named by its principal. That replaces a contact enrolled
into a naapp-local account. The contract documents change in the follow-ups under
[Work this changes](#work-this-changes).
[Human confirmation started from `aw`](human-confirmation-from-aw.md)
(aweb-acwd.4) is how the holder creates its credential and then uses the
role.

Requirement: Bookshelf `kb/concepts/customer-agent-servers.md` at `5c83ed85`
(lines 21-24, and gap G-B at line 76). There are no naapp member accounts, and
the same verified human identity serves every naapp.

## Rulings

| Item | State | Ruling | Main tradeoff |
| --- | --- | --- | --- |
| H1. Added acts or a changed subject | Ruled | Three acts added to `aweb.owner-act/1`, which is additive | The contact acts stay in the vocabulary, unused, until a separate removal. |
| H2. Who may hold a role | Ruled | A current team member of human kind, checked at designation and on every use | An auditor who is not a team member cannot be a logs reader, and each use needs the registry. |
| H3. Lockout and recovery notices | Ruled | A notice-only email contact for the roles that declare one: in secrets, owners and issuers (D9a) | The contact receives notices only, never an enrolment or approval link. The 72-hour freeze and the hook event stay. |
| H4. Whose credential the act binds | Ruled | The controller act binds it. When the owner is not the holder, the two clients compare a fingerprint | Trust on first use rests on that comparison. |

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

- **`human-role.designate`**: `app_id`, `installation_id`, `role`, `principal`,
  `credential_sha256` and, for a role that declares one,
  `notice_contact_sha256`. It makes `principal` the holder of `role`, using
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
  `{"credential_id": <base64url>, "public_key": <base64url>, "rp_id": <text>}`.
  The first two are the authenticator's credential id and its COSE public key
  bytes, each unpadded base64url. `rp_id` is the hostname of `owner_acts.origin`
  for a browser passkey, the default, or exactly `aweb:` for the
  [optional security key](human-confirmation-from-aw.md#optional-a-security-key-from-the-terminal).
- `notice_contact_sha256` is B3's `contact_sha256` of the notice contact
  (`naapp-lib/src/aweb_naapp/runtime/passkeys/service.py:314`).

`app-role.designate`, `app-credential.recover` and `app-role.revoke` keep
their meaning. An app that declares a role with the human-role acts accepts no
contact act for that role (H1).

### Declaration

An `owner_acts.roles` entry keeps `name`, `label`, `description` and `acts`.
Its `acts` is a nonempty subset of the three human-role acts. It adds
`notice_contact`, a boolean that is true when designate and replace must name
one (H3). It drops `principal`, because every human role binds a principal,
and `prepare_tool`, for the reason in the next section.

### No prepare, no pending rows, no role tokens

Prepare had two jobs: to carry a token the app chose without deriving it from
the contact, and to commit the contact before the owner signed. With a
principal, neither applies. A principal is public and names the holder, so the
app keys the holder by (installation, role, principal), and the act names the
credential itself. A notice contact needs no prepare either: the act names
its hash, as `app-role.designate` names `contact_sha256`, and it is never a
key or a link. Removing prepare also removes:

- the prepare tool and its five fields;
- the pending rows and their lifetimes;
- `secrets:owner-act` and the per-member prepare limit;
- the client's `prepare_mismatch` checks;
- the delivery contract's section on why a member gains nothing from prepare.

A member takes no part in designation.

### Delivery body and stage 3

The body is `signing`, `signature` and, for designate and replace,
`credential`: `{"credential_id", "public_key", "rp_id"}` in the same
encoding, plus `notice_contact` when the role declares one. Both are refused
for revoke. The app sends no enrolment link.

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
  `credential_sha256`, a COSE key with no private parameters, by B3's
  existing retention check (`naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py:395-408`),
  and an `rp_id` that is the hostname of the act's `aud` or, where the app
  enables the optional profile, exactly `aweb:`;
- for designate and replace of a role that declares one: `notice_contact`
  against `notice_contact_sha256`; otherwise both are absent;
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
  credential and its `rp_id` stored at sign count 0 and in effect at once,
  and records the notice contact. The holder changes that contact later
  through B3's existing contact change, under its passkey.
- **Replace** retires the current credential at once and puts the replacement
  in effect at the end of the cooling-off. Until then, the holder's approvals and the widening changes
  it gates are frozen.
- **Revoke** ends the holding.

Each emits `post-governance-hook` with `authority: owner_act`.

### Use

A holder logs in and approves with the bound credential: by default in a
browser on the app's human origin, through B3's existing login and approval
ceremonies, which `aw` opens
([Human confirmation started from `aw`](human-confirmation-from-aw.md)). A
holding bound under `aweb:` uses the optional security key from `aw` instead.
Each assertion is verified under the bound `rp_id` only. Each login and each
approval re-checks that `principal` is still a current human member. An
unknown answer refuses, and a revoked membership ends the holder's authority.
A human role has no enrolment link; the link-based enrolment stays for
contact roles.

### Reading a holding

Holdings live in one store, `aweb_naapp`'s, with one implementation for
every app: one table, one owner. Its writers are the human-role acts'
effects and the certificate refresh below. An app declares its roles and
calls the store. A consumer, such as a console handoff, maps the read and
the hold onto its own interface. It never reads, locks or writes the
holding table itself, and keeps no copy of a holding's fields or
certificate. The signatures, in `aweb_naapp` terms:

```python
@dataclass(frozen=True)
class HumanRoleHolding:
    installation_id: str
    team_id: str
    role: str
    principal: str
    b3_scope: str
    subject: str | None
    held_since: datetime
    certificate: bytes | None


async def read_holding(
    tx: TransactionManager,
    *,
    installation: AdmittedInstallation,
    role: str,
    principal: str,
) -> HumanRoleHolding | None: ...


async def hold_holding(
    tx: TransactionManager,
    *,
    installation: AdmittedInstallation,
    role: str,
    principal: str,
) -> HumanRoleHolding | None: ...


async def refresh_holding_certificate(
    tx: TransactionManager,
    *,
    holding: HumanRoleHolding,
    certificate: bytes,
) -> bool: ...
```

- **Where they run.** In the caller's transaction, by SQL only. Neither
  does a network or registry read or refreshes anything. `read_holding`
  takes no lock: it projects a target before an effect transaction, and its
  result protects nothing by itself.
- **The hold.** `hold_holding` returns the same result as `read_holding`,
  and locks what it read `FOR SHARE` until the caller's transaction ends:
  the holding row, and the B3 approver and credential rows that the holding's
  writers change with it. Before an effect, the caller holds the holding
  and compares `held_since` and `subject` with the target it projected. A
  difference, or `None`, refuses the effect. A revoke or replace therefore
  cannot commit between the comparison and the effect.
- **Lock order.** The caller takes the installation's dispatch fence first,
  then `hold_holding`, then B3's current-approver preparation, then its own
  approval, change-set and session rows. Every writer of the holding row
  locks it `FOR UPDATE` in the same order, after the fence and before any B3
  row: designate, replace and revoke under the owner act (stage 3), the
  certificate refresh, and any app path that ends a holding. On the hold side, secrets' owner holding
  takes this order with `hold_role` (`naapp-lib/src/aweb_naapp/roles/__init__.py:158`) on the
  role row as its hold.
- **No holding.** It returns `None` when (installation, role, principal) has
  no current holding: never designated, or revoked. It also returns `None`
  for a role the app does not declare with the human-role acts, and for a
  `principal` that is not a `did:aw`.
- **The key.** `installation_id` and `team_id` are the admitted
  installation's. `b3_scope` is derived from the installation, the team, the
  role and the principal only, as secrets derives an owner's scope
  (`naapp/secrets/src/aweb_secrets/owners.py:43-45`). A holding is never
  read from a contact hash. A slot made by `app-role.designate` before the
  app declared the role with the human-role acts is not a holding, and the
  read never returns one.
- **The credential.** `subject` is B3's subject for the credential that can
  log in. It is `None` while none can: from a replace until the end of its
  cooling-off. The holding still exists then, so the caller refuses the login
  without treating the role as unheld.
- **The holding's version.** `held_since` is the database's
  `clock_timestamp()` in the designate transaction that creates the holding,
  never a request's or client's time. Consumers compare it only for
  equality. A replace keeps it. A revoke followed by a designate gives a new
  value, so a consumer that bound a session to the earlier holding sees that
  it changed. A consumer's binding to a holding uses only installation, team,
  role, principal and `held_since`, none of which is secret.
- **The certificate.** `certificate` is the exact bytes of the holder's
  team certificate, retained with the holding
  ([Membership evidence](human-confirmation-from-aw.md#membership-evidence)).
  Designate and replace write the bytes in their body, after stage 3 has
  verified them. A `session` handoff whose login succeeds replaces them
  through `refresh_holding_certificate`, once the handoff has verified the
  new certificate and its team and principal equal the holding's. The
  refresh writes nothing and returns false when the holding's `held_since`
  no longer equals the one given. It runs in its own short transaction,
  after the login's transaction has committed: the installation fence, then
  the refresh, and no B3 or session row. It never runs in a transaction
  that holds the holding `FOR SHARE`, because upgrading that lock deadlocks
  two concurrent logins for one holding. The certificate was verified in
  the login under its original deadline, so committing it afterwards grants
  nothing. When the refresh returns false, the session keeps its own
  certificate and nothing else changes; the next use fails the holding
  comparison. It is `None` only for a holding that has
  none retained, such as one made before this contract. Its use then
  refuses with `403 principal_not_member` until a `session` handoff
  refreshes it. A session keeps the certificate its own handoff presented,
  with the session and for at most its lifetime. That is a session record,
  not a copy of the holding's.
- **Membership and kind are not read here.** Each use re-checks that
  `principal` is a current human member ([Use](#use)). That check is the
  runtime's shared exact-principal check
  (`aweb_naapp.runtime.human_member.check_human_member`). The caller runs it
  before its effect transaction and keeps its proof fresh around each read
  and hold.
  The read runs no copy of that check. A holding whose principal has left
  the team still reads as a holding, so revoke can target it (stage 3
  above), and the shared check refuses its use.

### What the owner's client shows and signs

The client shows:

- the app (id and origin);
- the role (app and `label`);
- the act;
- the principal, with its address and kind as the registry reports them;
- the credential's kind (a browser passkey at the origin's hostname, or a
  security key) and its fingerprint: the first 16 hex characters of
  `credential_sha256`, in groups of four;
- the notice contact, when the role declares one.

It then signs. The holder's `aw` obtains the public credential through a
[`credential` handoff](human-confirmation-from-aw.md#the-handoff): the
browser creates the passkey on the app's human origin and B3 verifies the
registration. When the owner is the holder, one client runs the handoff and
signs the act in one sitting. When the holder is someone else, the holder's
client exports the public credential, and the owner signs only after the two
clients show the same fingerprint (H4). That comparison helps only
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
  user-verified assertion by the bound credential, under its bound `rp_id`.
  No attestation is claimed. A `credential` handoff authorizes nothing: only
  the controller act binds what it returns.
- **What membership does.** Membership is required but never sufficient: the
  holding comes only from the owner act, and resource grants stay separate.

## Work this changes

Each is filed as one reviewed change:

- the contract text in [owner-act.md](../owner-act.md#acts-and-subjects),
  [owner-act-delivery.md](../owner-act-delivery.md) and
  [app-manifest.md](../app-manifest.md#manifest-version-3);
- the vector, generator and test under `naapp-lib/tests/hooks/`, re-frozen by
  the same review;
- the follow-ups filed for 16.38 (16.40 to 16.45): their prepare and
  enrolment-link work drops, and the human-role acts and the handoff replace
  it;
- C3's `aw app role designate|revoke` and `aw app credential replace`, naming
  `--principal` and, where the role declares one, the notice contact;
- the `credential` handoff (aweb-acwd.4);
- the holding store in `aweb_naapp`, with its writers, read, hold and
  certificate refresh, to the signatures in
  [Reading a holding](#reading-a-holding), and logs' adoption of it
  (aweb-acgh.16.44). The console handoff reads a holding's certificate
  through it, keeps no copy of a holding, and refreshes the certificate after
  its login commits, with a test of two concurrent logins for one holding.
