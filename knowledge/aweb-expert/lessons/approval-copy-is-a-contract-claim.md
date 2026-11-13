---
type: Lesson
title: Approval copy is a contract claim
description: Plain-language copy on an approval screen states what the person approves, so write one sentence per independent fact and check each against the contract clause that defines it; simpler wording tends to merge responsibility with membership or overclaim what admission withholds.
tags: [lesson, review, ux, human-assurance, membership]
timestamp: 2026-11-13
---

The words a person reads on an approval screen are the act they approve. A
UX simplification that reads well can silently change that act, and nothing
in the code goes red when it does.

In the human-assurance contract (`docs/human-assurance-contract.md`),
responsibility and membership are independent facts. Responsibility follows
the issuance chain: grandchild issuance stays with its actual eligible parent,
and root-side admission supplies membership separately. Admission also grants
no resource access beyond what already applicable team and role policy gives
ordinary members.

During the signer UX review in acxy.16 (2026-11-13), proposed copy for
endorsing a root told the person they were responsible for every agent the
root adds. That merges membership into responsibility: an agent the root
admits to a team is not one the person becomes responsible for. Copy that
promised "no access to secrets" overclaimed in the other direction; the
contract promises only no access beyond ordinary members'. The UX owner
accepted the correction.

# How to apply

- Write one sentence per independent fact: who issued the identity, who may
  join the team, what access joining gives.
- Check each sentence against the clause that defines it before the copy goes
  to the UX owner or to Juan. A shorter sentence that covers two facts is
  usually wrong about one of them.
- Prefer the contract's own limit ("nothing beyond what ordinary members
  get") over a stronger, friendlier promise the contract does not make.

The same separation governs the design side:
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
keeps responsibility and membership as separate inputs, and
[vary independent assurance dimensions in review](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md)
is the way to test that an implementation keeps them apart.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/responsibility-follows-creation-not-admission.md. The two contract
clauses were read in `docs/human-assurance-contract.md` at 859e07567 and on
main at 0bd6bd986. The proposed wording and its acceptance by the UX owner
are the source's report.
