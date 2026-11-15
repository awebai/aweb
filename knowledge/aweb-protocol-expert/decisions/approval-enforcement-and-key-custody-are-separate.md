---
type: Decision
title: Approval, application enforcement and key custody are separate
description: An independent approval service issues one receipt per exact act, bound to the enforcing application's nonce and deadline; each application enforces its own human-approval policy; a separate key holder creates and holds organization keys. Registry protection and portable membership are retired as foundations. Human-accepted direction; no format, implementation or release is implied.
tags: [decision, architecture, approval, authority, custody, supersession]
timestamp: 2026-11-15
---

The human accepted a replacement architecture for human approval on
2026-11-15. It replaces the portable-membership and registry-protection
direction outright. It is not an incremental extension of that direction.

# Decision

- **Approval is an independent service.** It lives in its own repository and
  produces a receipt for one exact act. The receipt is bound to the enforcing
  application's nonce and deadline.
- **Each application enforces its own policy.** The application decides which
  acts need a human and enforces that decision. The approval service does not.
- **Organization keys live with a separate key holder.** Organization keys are
  created and held inside their own key-holder boundary, apart from the
  approval service and the applications.
- **Human-ID evidence is adjacent.** It travels beside the identity chain and is
  reported for each link. It is not folded into the chain.
- **The registry gains no approval machinery.** The approval architecture adds
  no human-approval or team-protection mechanism to the registry.

# Enforcement and proof boundary

- **The approval service holds no keys.** It holds neither the human's
  enrolled private keys nor organization keys. Its output is evidence of the
  human's enrolled-key assertion over one exact act, not a signature by
  anyone else's key.
- **The receipt is portable evidence for one enforcer.** It is bound to that
  enforcer's audience, its one-time value and the original deadline. Nothing
  later restarts the deadline.
- **The enforcer checks and consumes.** It checks that the asserting
  credential belongs to a person it trusts for the act, and it consumes the
  replay-sensitive one-time value together with its own effect, not before
  and apart from it.
- **A local decision is not portable authority.** A login, or an approval
  decision held only inside one service process, is not this evidence.
  Reusable approval or passkey code extracted from such a service must not
  carry process-local transaction authority with it.
- **The registry asserts no custody or protection mode.** It records no
  claim about how an organization's keys are held or whether a team is
  protected, and no request observes a registry protection state.

The key holder owns organization keys, its closed signing rules and its
signing audit. Applications own which acts need a human and what effect an
approved act has.

**Retiring retained effects does not weaken proof.** Removing the signer's
retained-effects engine does not permit replacing the human's proof with a
service-authored success summary. The raw WebAuthn assertion, the exact
signed bytes and independent verification against a trusted key remain
requirements, as [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
records.

# Why

The boundary keeps human consent tied to the exact act that an application
enforces. It does not merge approval, application policy and organization-key
custody into one registry or membership mechanism.

# Retired foundations

Do not build the replacement on any of these:

- registry team-protection bindings, proofs or receipts;
- registry protection and membership observation, including request-rate
  protection observations;
- the detached protected-effect header;
- the signer's separate service key and its retained-effects engine;
- custody-field plans, and an in-process hosted signer.

Review acknowledgements given for those mechanisms are historical. They do not
authorize building on them and do not transfer to the approval service. The
portable-membership roster convergence target is not a requirement of the new
architecture. The general practice of keeping immutable evidence, current
authority and actual effects apart is still useful.

# Scope and status

This is an accepted direction. It does not describe current code, which still
follows the older design. It does not define a receipt codec, an identity
migration, a deployment or release authority. New formats and implementations
need their own assigned review.

It does not relax any existing guarantee. Independent later verification and
privacy stay governed as they are; a change to them still needs the ruling
that [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
requires. [One principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md)
remains in force.

**Acceptance: source-reported.** The source reports that the OSS coordinator
relayed the human's decision on 2026-11-15, and a second coordination record
accepted closing the work on the retired direction. The harvester could not
read either record. The source read only the coordinator's decision brief, not
the full architecture page, so this concept records only that brief.

The enforcement and proof boundary is also source-reported: a second source
reports that the coordinator relayed the human's 2026-11-15 approval of it,
including the express removal of the registry protection binding, the
signer's separate service key and per-request protection observation. The
same source reports that the approval library's owner agrees with the
process-local versus portable distinction; that is a source constraint, not a
second human ruling. The harvester could not read these records. Neither
source claims implementation, verification or deployment.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-15; notes/separate-approval-enforcement-key-custody.md.
Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-embedding, 2026-11-15; notes/approval-evidence-is-not-key-custody.md.
