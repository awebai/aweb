---
type: Decision
title: An absent team-auth header answers <name>_missing
description: In naapp-lib's team auth, an absent or blank required header answers <name>_missing and a present but malformed one answers <name>_invalid, on every route that reads the header; the signed payload's presence is checked before awid's verifier runs, so no awid verifier text is mapped to a code.
tags: [decision, naapps, team-auth, refusals, contracts]
timestamp: 2026-11-24
---

Ruled by the Secrets lane (ruling e2250e73, relayed by the naapps coordinator
in 0edd6c08) during task aweb-advy, 2026-11-25 by the source's clock. This is a
lane ruling and the source reports it. No human acceptance is claimed. It
refines the coding of naapp team-auth refusals as `{"code", "message"}`
(harvest PR awebai/aweb#246, pending when this was written).

# The decision

One rule covers every required team-auth request header:

- **Absent or blank** answers `<name>_missing`: `authorization_missing`,
  `timestamp_missing`, `signed_payload_missing`, `certificate_missing`.
- **Present but malformed** answers `<name>_invalid`.
- The rule holds on every route that reads the header. The same absent
  header never gets two codes depending on the route or the code path.
- **The signed payload's presence is checked in naapp before awid's request
  verifier is called.** The request path and the payload-bytes path then answer
  the same code, and naapp still never reads awid's verifier text to pick a
  code. Every other awid verifier error stays `signed_payload_invalid`.

# Why

- Review rejected the first version because one absent header answered two
  codes depending on the route. A client could not branch on "you forgot the
  header". The rule was fixed before the codes were released, because a code is
  hard to change once clients branch on it.
- A future change that adds a header or a route would otherwise answer
  `*_invalid` for an absent header again.

# Rejected

- **Mapping awid's "missing ... header" verifier text to `*_missing`.** It
  would break the rule that naapp never maps awid verifier text to codes. The
  presence check gives the same code without reading awid's wording.

# How to apply

- A new required header gets both codes, `<name>_missing` and `<name>_invalid`.
  Check its presence in naapp, before any delegated verifier runs.
- A new route that reads an existing header uses the same two codes.
- Test the absent case on each path. In review, disabling the presence check
  failed exactly the `signed_payload_missing` case.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-24; notes/advy-plan.md. The harvester checked that naapp PR #43 merged
as d16d0b2d, that main run 45555486533 at d16d0b2d is green, that commits
7102acd0 (test) and 048091fe (fix) exist, and that `team_auth.py` at d16d0b2d
answers the four `*_missing` codes and `signed_payload_invalid` for a malformed
payload. The review verdicts (rejection 4cebd302, approval c85062cd) are
source-reported.
