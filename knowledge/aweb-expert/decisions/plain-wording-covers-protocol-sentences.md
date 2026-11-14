---
type: Decision
title: Plain wording covers frozen protocol sentences too
description: Everything a person reads while approving uses only words someone who has done onboarding knows; a frozen, pinned protocol sentence is not exempt and is changed through the protocol path, not waived; the coordinator takes these copy decisions under the rule without a separate operator round, and every factual sentence is checked against the code before it ships.
tags: [decision, ux, approval, copy, protocol, human-assurance]
timestamp: 2026-11-13
---

Decided on 2026-11-13 by the OSS coordinator (rulings 4e29bc2c and b700c927)
while applying the operator's settled plain-wording rule to the protected
signer's approval copy. The operator's rule is source-reported, not verified
by the harvester.

# Decision

- **The rule.** Anything a person reads during an approval uses only words a
  person who has done onboarding knows: team, agent, member, root agent,
  passkey, approve, owner. Mechanism words (membership certificate,
  endorsement, signer, principal, operation, resource permissions) move to
  Technical details or are reworded.
- **Frozen protocol sentences are covered.** A sentence pinned by the
  protocol, such as the root-endorsement responsibility statement, is not an
  exception. When it fails the rule it is changed through the protocol path:
  the definition owner changes it, the security reviewer ACKs the text, and
  it rides a coordinated `aw` release. It is never waived because it is
  frozen.
- **Who decides.** The coordinator takes copy decisions of this kind under
  the rule. They are not sent to the operator for a separate round before the
  walkthrough.
- **Facts are checked.** Every factual sentence is checked against the code
  before it ships. Plain wording that reads well can be false.

# Rationale

A sentence that is frozen for protocol reasons is read by the same person as
any other approval copy, so freezing it changes how it is changed, not
whether the rule applies. Without this ruling a future instance would treat
frozen copy as untouchable, or escalate each such sentence to the operator,
who has already set the rule.

The root responsibility statement was the first case. "Everything this root
spawns counts as yours for human responsibility; this grants no resource
permissions." became "Agents it adds count as yours. It gets no other
access." The change rode the intent_v1 `aw` release, which already forced an
upgrade, so it cost no extra client churn.

During the same copy pass three proposed sentences were found false against
the code and replaced before landing. Simpler wording invites this: see
[subject_ineligible can mean the approver or the target](/aweb-expert/lessons/subject-ineligible-can-mean-approver-or-target.md)
for one way a plain refusal sentence goes wrong.

# Consequences

- [Converged decisions stay frozen](/aweb-expert/lessons/converged-decisions-stay-frozen.md)
  is about a coordinator reopening a functionally fine choice. A sentence the
  person cannot read is not functionally fine, so that lesson does not shield
  it.
- [Drive coordination to done](/aweb-expert/lessons/drive-coordination-to-done.md)
  already says to escalate only genuine product or authority forks; a copy
  choice under a settled rule is not one.

# Status

Verified on main: commit 0140a0db1 ("Use the approved plain root-endorsement
responsibility statement") is reached by merge 940cbe65b, and the new
statement is the one in `docs/protected-operations-v1.json` and the generated
CLI definitions. The security text ACK (9c2616a2) and the coordinator rulings
are the source's report.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/plain-wording-covers-protocol-sentences.md.
