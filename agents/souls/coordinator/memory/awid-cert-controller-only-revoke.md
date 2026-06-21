---
name: awid-cert-controller-only-revoke
description: awid team-certificate model is deliberately controller-only for add AND revoke. The issuer_did_key column + revoke-broadening (revoke-by-issuer-if-member OR holder) was investigated end-to-end and SCRAPPED as YAGNI on 2026-06-21. Do not reopen unless member-mediated invites become real scope.
metadata:
  type: project
---

On 2026-06-21 the team investigated adding to awid: (1) an `issuer_did_key`
column on `team_certificates` (migration 008, additive/nullable), and (2)
broadening `revoke_certificate` auth from controller-only to
controller-OR-issuer-if-still-member-OR-holder. Tracked as epic `default-aabq`
(.7 aw team-add, .8 awid schema+revoke, .9/.10 AC orphan bugs). Full design note
existed at `docs/restructuring/team-cert-issuer-seam.md`.

**Juan scrapped the awid change entirely.** Reasoning (YAGNI, and correct): the
distinct "revoke by issuer" capability only differs from "revoke by controller"
once a **non-controller member can add members** (member-mediated invites) — and
that is out of scope. Until then, every add is controller-authorized, so
`issuer == controller` and the column + broadened revoke buy nothing real.

**The settled model:** awid certs are **controller-only for both add and
revoke**. `register_certificate` and `revoke_certificate` are gated by
`_require_team_controller` (`awid/.../routes/teams.py:74`). In all hosting modes
the signer is the controller — self-hosted presents the team-key signature
locally, hosted has AC mint server-side by decrypting the controller key. No
individual inviter DID is captured anywhere, by design. **awid was not changed.**

**How to apply:** do NOT re-propose the issuer column or revoke-broadening as a
standalone improvement — it was deliberately declined. It only becomes worth
building if/when member-mediated invites enter scope; at that point the seam is
3-lane (self-hosted local signer / hosted AC mint / `add-member` is also a
register entrypoint). See [[dont-reopen-converged-decisions]],
[[correctness-over-momentum]].

**Survives the scrap:** the AC re-accept stale-did idempotency bug
(`aabq.10`) and orphan cleanup (`aabq.9`) are REAL bugs independent of the
scrapped feature — re-accept producing orphaned identities is wrong regardless.
Kept alive under ac-coordinator on their own merit.
