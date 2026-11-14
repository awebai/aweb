---
type: Lesson
title: Per-approver attribution comes from the approval record, not the signer audit
description: The protected signer's local audit names the governed human as actor for every approver of a scope, so "decided by you" and any other per-approver wording must compare the approval record's decided_by.subject with the console session subject.
tags: [lesson, protected-signer, owner-page, audit, review]
timestamp: 2026-11-13
---

A scope can have more than one approver, for example two owners. The protected
signer admits each of them as the same governed human: the admitted principal
is `context.human_id`, and the signer's local audit rows carry that principal
as actor. The audit therefore cannot tell two approvers apart.

The owner page first marked "decided by you" from the audit actor. With two
owners, every owner's decisions showed as yours. Two reviewers found it, and
the fix on main (3b3ad5245, `_deciders` in the server's owner page module)
reads the approval record instead. There `decided_by.subject` is the
per-approver passkey subject, the same subject the console session carries.

How to apply: any new surface that says who decided (owner page, history,
notices, mail) compares `decided_by.subject` with the session subject. When
reviewing such a surface, test it with two approvers on one scope; a
single-owner test passes either way.

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/decided-by-you-needs-approval-decider.md. The harvester checked that
3b3ad5245 is on main and that its `_deciders` compares
`approval.decided_by.subject` with the session subject.
