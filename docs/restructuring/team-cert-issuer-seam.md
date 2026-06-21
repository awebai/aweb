# Team-Certificate Issuer Seam (3-lane design note) — SUPERSEDED / SCRAPPED

> **SUPERSEDED 2026-06-21 (Juan, YAGNI).** This design is NOT being built.
> Decision: as long as only the team controller can add and revoke members
> (member-mediated invites are out of scope), there is no distinct
> revoke-by-issuer capability to enable, so recording an issuer and broadening
> revoke buy nothing now. awid stays controller-only: no migration 008, no
> `issuer_did_key`, no revoke-auth change. `aabq.8` is closed as superseded;
> `aabq.7` folded into the materialize fixes; the hosted issuer-threading task
> was never created. **What survives independently:** `aabq.10` (AC re-accept
> stale-did idempotency → orphans) and `aabq.9` (orphan cleanup) are real bugs
> regardless of the issuer feature and remain tracked under ac-coordinator.
> Kept below for the record (the invite/accept flow trace in §1 is still accurate
> and useful reference).

Status: draft (2026-06-21), for review by aweb-coordinator (awid) + ac-coordinator
(AC hosted). Owner of the note: aw-coordinator. Pairs with epic `default-aabq`
(.7 team-add, .8 awid issuer + revoke-auth, .10 AC accept idempotency).

Purpose: lock the seam where a team certificate's **issuer** is determined, so
awid's new `issuer_did_key` column (`.8`) and the team-add flow (`.7`) and the
hosted mint (AC) are designed once, not three times.

## 0. The decision being enabled (Juan)

A team certificate may be revoked by **any of**:
- the **team controller** (kept — the admin must always be able to remove
  anyone), OR
- the **issuer**, provided the issuer is still a member of the team, OR
- the **holder** of the certificate (self-removal).

For "revoke by issuer-if-still-member" to be a *distinct* capability (not just a
synonym for "revoke by controller"), the recorded issuer must be the
**individual who authorized the add**, which only differs from the controller
once a non-controller member can invite. See §3.

## 1. The invite/accept flow across hosting options (verified in code)

The fork is **where the team controller key lives**, dispatched implicitly by
`TeamKeyExists` (`cli/go/cmd/aw/id_team.go:550`):

| | issues invite | joiner talks to | **signs/mints the member cert** | issuer today |
|---|---|---|---|---|
| **Self-hosted / local-dev** | local controller-key holder; unsigned token+secret (`createTeamInviteToken`, `id_team.go:807`) | local invite store + **local team key** | the **client**, locally: `SignTeamCertificate(teamKey)` (`certificate.go:50`), registers in awid signed by the team key (`RegisterCertificate`, `registry_team.go:286`) | the team/controller key |
| **Hosted (aweb.ai)** | AC `/spawn/create-invite` (`id_team.go:854`); `aw_inv_` token | **AC** `/spawn/accept-invite`, signed with the joiner's fresh did:key | **AC server**: decrypts the controller key, `mint_team_certificate` (`ac team_cert_mint.py:208-223`); CLI never holds a team key, never calls awid `POST /certificates` | AC (the controller) |

The **invite token carries no minting authority** in either mode — it is a
validated pointer (one-time secret / opaque server handle). Authority lives with
the controller-key holder (local client vs AC server).

awid `register_certificate` is gated by `_require_team_controller`
(`awid/.../routes/teams.py:74-95`): the request must be signed by
`team_did_key`. So **today the authorizer is the controller in both modes** —
self-hosted presents the team-key signature itself; hosted has AC present it.
**No individual inviter did is captured anywhere today** (confirmed by
aweb-coordinator).

## 2. The seam: where `issuer_did_key` comes from

`issuer_did_key` = the did that **authorized** the add, and it must be an
**authenticated** value (the inviter signs), never trusted from a request body
(aweb-coordinator's hard requirement).

- **Self-hosted has TWO register entrypoints** (aweb-coordinator): (a)
  invite/accept (same-machine), and (b) **`aw id team add-member`**
  (`runTeamAddMember`, cross-machine BYOT) which also signs with the team key
  (`SignTeamCertificate(teamKey)`) and calls `RegisterCertificate` directly.
  Issuer-capture must cover **both**, not just the `TeamInvite` record. Both
  write awid's `team_certificates`, so awid's `issuer_did_key` column (`.8`)
  covers self-hosted.
- **Hosted — the certs are NOT in awid** (verified): hosted local-scope member
  certs are stored **only in AC's DB** — `agents.team_cert_blob` +
  `aweb_cloud.cloud_agent_certificates` (`ac .../team_cert_mint.py:224-240`).
  The CLI never calls awid `POST /certificates` for local-scope hosted members;
  awid registration happens only on the global/persistent path. **awid's
  `issuer_did_key` column therefore never sees hosted local-scope certs.** AC's
  `cloud_agent_certificates` has **no issuer column today**
  (`ac migrations/001_initial.sql:237`). AC *does* capture the inviter
  (`created_by_agent_id`/`created_by_principal_id` on `spawn_invite_tokens`,
  `migrations/001_initial.sql:1035`) but **drops it** before the cert
  (`accept_invite` never threads it to the mint).

**Consequence**: a uniform issuer across both modes is NOT an awid-only change.
Self-hosted is awid (`.8`). Hosted requires **AC-DB schema + plumbing**: a new
issuer column on `cloud_agent_certificates` (and/or the cert blob shape in
`team_cert_mint.py`), plus threading `created_by_*` from the invite row through
`accept_invite → _bootstrap_identity_in_team → ensure_stored_agent_team_certificate`,
and the issuer-or-holder revoke-auth on AC's revoke path. That is a separate
AC-lane task, not aweb-coordinator's awid 008.

## 3. The latency point (aweb-coordinator)

Today every add is controller-authorized, so if we record "the authorizer,"
`issuer_did_key` == the controller for every cert, and revoke-by-issuer is
functionally identical to revoke-by-controller. The issuer becomes a **distinct**
capability only when a **non-controller member can invite** (member-mediated
invites). That capability is **not built today** and is out of scope for the
first cut.

**Consequence**: recording the issuer now is correct and forward-compatible, but
its distinct value is latent. The first cut records whatever did authorized the
add (controller today); member-mediated invites later make it meaningful without
a schema change.

## 4. Ownership + sequencing

- **awid (`.8`, aweb-coordinator)**: migration 008 — additive, nullable
  `issuer_did_key` (never edits 001; existing rows stay NULL → fall back to
  controller/holder revoke, no regression). Broaden `revoke_certificate` auth to
  controller **OR** issuer-if-still-an-active-member **OR** holder. Expose issuer
  in `list_certificates`.
- **aw (`.7`, aw-coordinator)**: the team-add / who-signs-register path; capture
  + authenticate the inviter did for the self-hosted register; persist the
  generated key before calling AC (idempotency, see `.10`).
- **AC `.10` (ac-coordinator)** — the re-accept stale-did **idempotency fix
  ONLY** (key-aware branch: presented==stored → idempotent re-mint; presented!=
  stored → 409). Kept landable-first, NOT bundled with issuer work, so it ships
  regardless of A/B. Must land before `.8`.
- **AC hosted issuer-threading (separate task, ac-coordinator)** — a new issuer
  column on `cloud_agent_certificates` + thread `created_by_*` through the mint +
  issuer-or-holder revoke on AC's revoke path. Timing follows Juan's A/B (§5).
  This is the AC-DB counterpart to awid `.8`; without it hosted certs have no
  issuer.

**Dependency**: `.8` depends on `.10` (stale dids would corrupt
revoke-by-issuer/holder).

## 5. Open decision (Juan) — rollout timing

Two options for the **issuer-capture plumbing** (the column + revoke-auth in `.8`
are additive either way):

- **A. Self-hosted issuer first, hosted as fast-follow** *(recommended by both
  aw- and aweb-coordinator)*: ship awid 008 + broadened revoke-auth now;
  self-hosted captures the issuer at register; hosted certs stay NULL-issuer
  (controller/holder revoke still cover them) until AC threads the inviter did
  through its mint (rides in with `.10`). Decouples the awid migration from AC
  mint-plumbing; no regression.
- **B. Hosted now**: couple the awid work to the new AC mint-plumbing so hosted
  certs carry an issuer from day one. More correct out of the gate, but `.8`
  waits on AC.

Pending Juan's call (in flight via aweb-coordinator). On `A`, aweb-coordinator
can spawn the awid build immediately.
