---
type: Decision
title: Grant seats verify the owner log key through the team key recorded in the grant
description: A grant seat, which holds no team certificate, verifies the team's owner log-key record against the team_did_key that aw id grant mint copies into grant.yaml from the resident's team certificate; the field grants nothing, a grant minted without it fails closed with no local log and no plaintext until re-minted, and copying the certificate into the grant home or asking the custody socket per write were rejected. Accepted; on main.
tags: [decision, aw-cli, local-logs, owner-log-key, session-grants, custody]
timestamp: 2026-11-13
---

**Status (verified 2026-11-19):** accepted by the operator on 2026-11-13 as an
identity-path change. The acceptance is **source-reported**: the OSS
coordinator relayed it by mail, and the merge commit names it. On main as
b45e0b698 (change 73e62064a). The mechanics are in `docs/identity.md`
(`grant.yaml` and `team_did_key`) and `docs/configuration.md` "Local Message
Logs".

# Decision

Local message logs are sealed to the team's owner log key, whose public record
an agent host verifies against the team key in its own team certificate. A
**grant seat** acts through a session-grant identity home that holds no team
certificate, so it needs another source for that team key.

- `aw id grant mint` reads the resident's team certificate **before** the
  server mint and records its team key as `team_did_key` in the grant's
  `grant.yaml`.
- A grant seat verifies the owner log-key record against that recorded key.
- The field is additive and optional. It is read **only** for log-key
  verification and **grants nothing**: no code may treat it as membership,
  team authority or a substitute certificate.
- A grant minted before the field existed **fails closed**: no local log and
  no plaintext fallback. The refusal says to mint the grant again, and
  `aw doctor`, run as a grant seat, reports the same condition. That refusal
  is the expected behaviour for old grants, not a bug to work around.
- The trust is the same as a local seat's `team-certs/`: both are files the
  same OS user wrote.

# Rejected alternatives

- **Copying the team certificate into the grant home.** It breaks the
  invariant that a grant home holds only the session credential, and code that
  treats a present certificate as root identity state would misread the grant
  home.
- **Asking the custody socket on each write.** Logging would depend on a
  running custody service, it would not help grants minted without custody,
  and it would change the custody status contract.

# When to revisit

A change that wants a grant seat to learn the team key some other way, or that
reads `team_did_key` for anything but log-key verification, reopens this
decision and needs the operator's ruling: it is an identity-path change.

This resolves the open limit "grant seats cannot verify the record" in the
local-log decision proposed in harvest PR 141 (local message logs are sealed to
an owner log key).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/grant-seats-verify-log-key-via-grant.md. Verified by the harvester on 2026-11-19: b45e0b698 is on main and its `docs/identity.md` and `docs/configuration.md` text matches the decision.
