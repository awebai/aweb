---
type: Lesson
title: subject_ineligible can mean the approver or the target
description: The protected signer raises subject_ineligible from its check of the approving human for every operation and from per-operation target checks, so a refusal sentence that names one cause can be false for the other; issuer_kind_forbidden comes from the approver check; write refusal copy true for every source until the definition owner splits the code.
tags: [lesson, protected-signing, refusals, copy, ux]
timestamp: 2026-11-13
---

Found on 2026-11-13 while fact-checking the signer UX copy pass.

The protected signer checks the governing human of every operation in
`server/src/aweb/protected_signing/authority.py` (`_own_human`). It raises
`subject_ineligible` when that human is not an enrolled, non-self-derived
identity of the domain, and `issuer_kind_forbidden` when it is not a human.
The per-operation target checks (removal, admission, root binding) also raise
`subject_ineligible`, about the target. So `subject_ineligible` means either
"the person approving is not eligible" or "the thing being acted on is not
eligible", and the code alone does not say which.

The proposal reported that `issuer_kind_forbidden` collides the same way. On
main at 940cbe65b the server raises it only from `_own_human`, so a sentence
for it should be about the approver. Recheck this if a target check starts
raising it.

A refusal sentence in an operation definition describes one cause. Read next
to the target check alone, the sentence looks right; it is wrong whenever the
approver check raised the code. For example, a sentence saying the target
"cannot become your root agent" is false when the approver's own identity
failed the check.

# How to apply

- When writing or reviewing a refusal sentence for `subject_ineligible`, list
  every place that can raise it for that operation: the approver check
  always, plus that operation's target checks.
- Write a sentence that is true for every source, or say plainly that it can
  mean either.
- When the approver check is the only signer-side source (as for
  `human-role.revoke`), write the sentence about the approver.
- Elimination route: separate codes for the approver and the target remove
  the ambiguity. That is a protocol change owned by the definition owner, not
  a copy fix.

Related: [plain wording covers frozen protocol sentences too](/aweb-expert/decisions/plain-wording-covers-protocol-sentences.md),
whose fact-check found this.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/refusal-codes-collide-approver-vs-target.md. The raise sites in
`authority.py`, `admission.py`, `removal.py` and `root_binding.py` were
checked on main at 940cbe65b. The review mail that flagged it (on 134abef19)
is the source's report.
