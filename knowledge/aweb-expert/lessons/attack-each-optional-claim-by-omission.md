---
type: Lesson
title: Attack each optional identity claim by omission
description: When a request may omit an identity claim and the server fills the principal from stored state, that stored principal must pass the same status and revocation checks as a claimed one; review probes each optional claim by leaving it out, from a principal whose stored identity is revoked or replaced, and checks the effective principal the handler records.
tags: [lesson, review, security, identity, authorization, testing]
timestamp: 2026-11-27
---

A security review on 2026-11-27 sent the same request twice from an enrolled
identity whose stable ID had been revoked. With the ID claimed, the server
refused it as revoked. Without the claim, the server accepted it and recorded
the revoked ID as the sender. The server ran its ID check against whatever the
request claimed. When nothing was claimed it checked only the signing key, and
the handler then took the stored ID from the identity's row as the principal,
after a key-binding check only. A team-certificate field that was allowed to be
absent had the same gap. The fix had not landed when this was harvested, so
the routes and field names are left out here.

# Why it recurs

- Test suites send the right claim and the wrong claim, and rarely send no
  claim at all.
- Code that fills a principal from a stored row reads as convenience, not as
  an authorization decision. A reviewer reading for the claimed path does not
  see that the fill skips the checks the claimed path runs.

# How to apply

- List every identity claim a request may leave out: an ID claim, a chain or
  delegation header, a certificate field the verifier treats as optional.
- For each one, send the request without it from a principal whose stored
  identity is revoked, replaced or otherwise ineligible. Hold everything else
  constant, including the signing key.
- Check the effective principal the handler records (the stored sender, actor
  or audit subject), not only the response status. A 200 that records the
  revoked identity is the defect.
- The fix belongs at the fill: a principal taken from stored state goes
  through the same status and revocation checks as a claimed one, in the same
  place. Keep each omission probe as a regression test; that test is the
  elimination route for this class.

This applies [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md)
to presence: hold the authorising fact (a revoked ID) constant and vary only
whether the claim is sent. The fill is one way to break the single principal
of [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md).
It is also a site the claimed-path review does not reach; see
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-acmj-security, 2026-11-27;
notes/omit-the-optional-claim.md. The source ran a real-stack probe: the
claimed-ID case was refused, and two omission cases were accepted. It reported
the finding as Required. All of this is source-reported, from one observed
instance. The harvester did not run the probe. Attack detail is withheld until
the fix is released.
