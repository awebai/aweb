---
type: Decision
title: Owner binding needs independent authorities
description: A verified responsible human is one input to owner binding; the actual human session, account association, current membership and action policy must agree in the binding transaction, with adoption available before enforcement.
tags: [decision, identity, authority, human-channels, membership, transactions]
timestamp: 2026-10-29
---

The human/channel binding design in aweb-acmj.19 rejected treating a verified
nearest-human result as ownership authority. That result answers who is
responsible. It does not establish key custody, current membership or consent.
A correct human match can coexist with accepted removal and surviving agent
rows; an administrator or linked mailbox can exist without the subject's
responsible human being present.

# Decision

Owner binding composes independent authorities for the same exact operation:
the actual human session and request protections; the verified account-to-human
association; the subject's current ancestry bound to its authenticated key;
current membership in the selected team with no accepted removal; and existing
consent, resource and portable approval checks. The locally mutable facts are
rechecked in the caller's binding transaction, with locks retained through
commit. No new ownership or removal store follows from this composition.

Resolve remote tree evidence before the effect locks. The ID-tree contract
checks its cache freshness once on acquisition; the portable approval's own
expiry and current revision still bind at application. Do not replace either
rule with a post-lock tree-age anchor, restart an expiry window, or claim a local
lock serializes the remote registry. The governing contracts, rather than a
general preference for more freshness checks, decide those boundaries.

Adoption is available before enabling the human-owner binding lane. Unknown or
unadopted subjects stay refused. A temporary legacy-owner exception adds a
second authority path and needs the operator's explicit approval; it is not
implied by the need to preserve existing clients. The released subject-signed
lane remains separate and unchanged.

# Rejected

Email or alias equality, mutable owner labels, pending key storage, registration
receipts, and API-key, grant or administrator substitution cannot establish the
required human action. A matching ancestry result alone also fails to close the
incomplete-retirement case: accepted membership removal must already deny the
new binding even while agent rows survive.

This applies [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md)
and [independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md)
to the specific composition needed by owner binding. The reducing-control
neighbor is [local stop is not new binding authority](/aweb-protocol-expert/lessons/local-stop-is-not-new-binding-authority.md).

# Provenance

Manual harvest on 2026-10-29 from `aweb-protocol-expert-acmj-binding`, notes
`owner-binding-needs-independent-authorities.md` and `okf-proposal.md`, task
aweb-acmj.19. The reviewed contract was authored at
`0618263546f09696f8362a443a41eb80a21a3f6a` and landed at
`053ff87bd6f8834fe19df614438a5eaeec71341a`;
`docs/human-channel-binding.md:88–154,291–308` records the predicate, transaction
boundary and activation order. This is a reviewed design decision, not evidence
that its consuming implementation or activation is complete.
