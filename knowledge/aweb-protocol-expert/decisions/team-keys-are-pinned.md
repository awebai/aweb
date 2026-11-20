---
type: Decision
title: Team keys are pinned; only a DNS-verified namespace-controller act moves a pin
description: A relying server pins the team key it first admits and uses the registry's key only when it equals the pin; a different key needs the namespace controller's kept rotate_team_key act, verified against the controller the domain's DNS names, and enforcement is staged behind AWEB_ENFORCE_TEAM_KEY_PINS. Registry trust, a team-controller key log and immediate enforcement were rejected. Accepted; on a review branch, not on main.
tags: [decision, awid, teams, keys, trust-model, security]
timestamp: 2026-11-12
---

The operator approved the design and the reversal of the earlier trust-model rule on
2026-11-12, and in a second ruling the same day accepted the staged flag, the
library scope and the anonymous key act. Both rulings are source-reported
(relayed by the aweb coordinator in mail, not readable here).

Why it was needed: on released code, a member forged under a team key that the
registry substituted connected and read the roster on the aweb server,
authenticated on a naapp-lib app and read the shelf on the library naapp. AWID
verified the namespace controller's `rotate_team_key` signature and then
discarded it, and the `create_team` act signs only domain and name, so no
server could check a team key against anything but the registry's word.

# Decision

- A relying server (the aweb server, every naapp, and the library naapp, which
  carries its own team-auth copy) pins the team key it first admits, and uses
  the registry's answer only when it equals the pin.
- A different key needs the namespace controller's `rotate_team_key` act. AWID
  keeps the act exactly as signed and serves it anonymously by exact key, so an
  app that reads only anonymous certificate status can still verify a private
  team's rotation.
- The verifier checks the act's signer against the controller that DNS names
  (`_awid.<domain>` or the nearest ancestor record), never the registry's
  `controller_did`, and requires the act to be newer than the act behind the
  pin. A rotate to the same key is a re-attestation that needs no new operation.
- Enforcement is staged behind `AWEB_ENFORCE_TEAM_KEY_PINS`, default off. While
  off, a mismatch logs one line `team_key_pin_mismatch ... enforced=false` and
  the registry's key is served. It is turned on only after hosted mismatches are
  counted and re-attested. Until then the registry-substitution gap stays open.

This replaces the earlier rule in `docs/trust-model.md` that the local
`teams.team_did_key` is a hint, not authority.

# Rejected

- **Trusting the registry's key** (the earlier "local key is a hint" rule): it
  is the gap the forged member walked through.
- **A key log signed by the team controller:** authority over a team's key
  belongs to the namespace controller, and recovery after the team key is lost
  has no old key to sign with.
- **Binding the first pin to DNS now:** the `create_team` act does not sign the
  key, so there is no act to check. Left as a named residual.
- **Enforcing at once:** it locks out every team rotated before acts were kept,
  and that set cannot be measured from OSS. See
  [a new authority over existing state is staged](/aweb-protocol-expert/lessons/a-new-authority-over-existing-state-is-staged.md).
- **Serving the key act only with team read access:** apps that read only
  anonymous certificate status could never verify a private team's rotation.

# Named residuals

First admission trusts the registry; delegated child namespaces with their own
key and no `_awid` record cannot present a DNS-verifiable act; the `local`
namespace has no DNS; an operator holding both the registry and the controller
is not constrained. Do not treat these as oversights to fix silently: each
needs its own design.

# Status

Implemented on the review branch `agents/aweb-protocol-expert-team-key-trust`,
not on main at harvest time (main at b16be85a2 still states the hint rule).
The branch's `docs/trust-model.md` section "Team-key pins" states the current
rule; this concept records why and what was rejected.

Related: [key authority history spans every path to the key](/aweb-protocol-expert/decisions/key-authority-history-spans-every-path.md)
(the same "every path" discipline, applied here to the aweb server, naapp-lib
and library), and
[unauthenticated input must not drive remote work](/aweb-protocol-expert/lessons/unauthenticated-input-must-not-drive-remote-work.md),
which this refines: verify against the controller that DNS names, not a
controller or key carried in the same registry response.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-12; notes/team-key-evidence-gaps.md, notes/library-has-its-own-team-auth-copy.md. Checked against the branch at d09139942.
