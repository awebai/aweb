# Team-Certificate Issuer Seam (3-lane design note)

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

- **Self-hosted**: the register is signed by the team key. To record an
  *individual* issuer distinct from the team key, the inviting agent's own did
  must be captured at **invite issuance** (in the `TeamInvite` record,
  authenticated by the inviter signing the invite with their own key) and
  carried to `register_certificate` as `issuer_did_key`, bound such that awid can
  verify it (e.g. the inviter's signature over the invite, presented at
  register).
- **Hosted**: AC already authenticates the inviter at `/spawn/create-invite`
  (team API key / session). AC threads that inviter identity through to
  `mint_team_certificate` and records it as `issuer_did_key` on the minted cert.
  The did is authenticated by AC's auth, not body-trusted.

Both paths populate the **same** nullable `issuer_did_key` column (awid `.8`).

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
- **AC (hosted mint + `.10`, ac-coordinator)**: thread the authenticated inviter
  did through `mint_team_certificate` as `issuer_did_key`; fix the re-accept
  stale-did idempotency bug (`.10`) — it must land or be scoped before `.8`,
  because revoke-by-issuer assumes recorded dids are the real current ones.

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
