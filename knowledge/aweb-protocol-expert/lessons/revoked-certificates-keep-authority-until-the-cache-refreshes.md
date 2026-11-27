---
type: Lesson
title: A revoked team certificate keeps authority until the cache refreshes
description: After a team-certificate revocation the aweb server accepts the certificate for up to 60 s fresh plus 60 s stale, so a removed member can mint a new identity grant and an existing grant keeps working; a registry write through another client does not invalidate the server's cache, and a test of revocation must treat the window as a timing case, never hide it by invalidating the cache in the harness.
tags: [lesson, revocation, certificates, grants, cache, testing]
timestamp: 2026-11-27
---

`docs/aweb-sot.md` ("Caching from awid") gives the TTLs: revocation lists are
fresh for 60 s, with one further 60 s stale window. It does not spell out
three consequences. The trust-web model-case runner found them on 2026-11-26,
and they are filed as task aweb-adyz.2.

- **Minting inside the window creates new authority after removal.** Ordinary
  team auth reads revocation evidence in cached mode
  (`read_certificate_standings` defaults to `EvidenceMode.CACHED` in
  `server/src/aweb/member_team_key.py`). That includes
  `POST /v1/identity-grants`, which authenticates through `get_team_identity`.
  So a removed member can mint a new identity grant during the window, and an
  existing grant keeps working. `/v1/connect` and a few control paths read
  fresh evidence.
- **A revocation written through another client leaves the server's cache
  stale.** The cached registry client invalidates entries only for its own
  writes. When a controller revokes through `aw` or any other client, the
  server sees nothing until its revocation entry expires.
- **Experiment, source-reported.** With only that team's cached revocation
  entry invalidated on the server's own client, the mint was refused with 401
  `certificate_revoked` and the grant read as dead. With the cache left alone,
  the mint was accepted and the grant read as live.

# How to apply

- A test or model case that checks "revocation ends authority" and acts
  immediately after the revoke will see acceptance. Treat it as a timing case:
  either read through the window or expect acceptance, and record the
  disagreement.
- Never "fix" the test by invalidating the server's cache inside the harness.
  That hides the real window from the gate.
- Whether minting a grant must read fresh revocation evidence is an open
  protocol question for the protocol owners. Keep it separate from the delay
  before an existing grant stops working. Live revocation is the primary
  control in
  [credential lifetime is optional team policy](/aweb-protocol-expert/decisions/credential-lifetime-is-optional-team-policy.md),
  so this window bounds what that control delivers today.

Found by the runner under
[model cases run against the real code](/aweb-protocol-expert/decisions/model-cases-run-against-the-real-code.md).
Related: [evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-model-cases, 2026-11-27; notes/revocation-window-is-model-a4.md.
On aweb main at 5c2ee7bad, the TTLs and cached/fresh modes were checked in
`docs/aweb-sot.md`, `docs/awid-sot.md` (member removal),
`server/src/aweb/member_team_key.py`, `server/src/aweb/team_auth_deps.py` and
`server/src/aweb/routes/identity_grants.py`. The experiment results are
source-reported.
