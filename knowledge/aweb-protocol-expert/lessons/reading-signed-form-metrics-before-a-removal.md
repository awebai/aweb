---
type: Lesson
title: Reading the signed-form metrics before a removal
description: The registry's accepted-authentication log lines count per operation and per worker process, and on the review branch also per signed form and client family, logged at 1 and powers of two, so a value is a lower bound for one operation in one process and equal maxima across operations mean similar volume, not a shared counter; silence on a legacy line means nothing without the covering line beside it.
tags: [lesson, awid, metrics, compatibility, controller-auth, signed-reads]
timestamp: 2026-11-17
---

# How the counter works

- The registry counts accepted signed requests in each worker process, keyed
  by operation (`counts[operation]` in `awid/src/awid/controller_request.py`
  as of the awid-service-v0.5.39 tag). On the review branch
  `agents/aweb-protocol-expert-team-key-trust` the key is form, operation and
  client family. The client family is `aw/<version>`, `python-httpx` or
  `other`, never the raw User-Agent.
- A line is logged when a count reaches 1 or a power of two. So a line's
  `value` is a lower bound for that operation in that process, not a total,
  and totals need the maximum per process, summed across processes.

# Misreadings to avoid

- **Equal maxima across operations mean similar volume, not a shared
  counter.** Each operation has its own count. The first production read of
  these lines took equal values to be one counter; the counter was per
  operation even before the client family was added.
- **Silence on the legacy line is not proof of no legacy clients** unless the
  covering line shows traffic in the same window. The covering counter exists
  so that "nobody sends the legacy form" can be told apart from "nobody sent
  anything".

# Removal criterion

The source's criterion for removing legacy acceptance: the covering aw client
and the hosted embedding's covering client are both deployed, then 14 days with
no legacy line. Whether to remove is Juan's decision, not the seat's. This
applies [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
("accepted until it is measured that nothing sends it") and governs when the
path-signed read of
[signed team reads share one verifier](/aweb-protocol-expert/decisions/signed-team-reads-share-one-verifier-not-one-policy.md)
may go.

Observed on 2026-11-17 from about 14 days of production logs: legacy
controller writes were in heavy use, most likely from the hosted embedding on
the pre-covering awid 0.5.39. Removal is not near until that client signs the
covering form.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/signed-team-read-design.md.
