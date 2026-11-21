---
type: Lesson
title: Vary independent assurance dimensions in review
description: To test an assurance label, find the fact that should authorise it, hold that fact constant and vary a neighbouring property that should not matter; an implementation can match every example while deriving the label from the wrong fact. When a change acts on an external answer, probe each neighbouring answer (another status with the same body code, the other provider or direction) with one probe or mutation, and suggest a predicate fix only with a mutation showing what it would drop.
tags: [lesson, review, trust-model, custody, testing, security, mutation]
timestamp: 2026-11-13
---

A review of human-channel message projection held a hosted-custodial native
author fixed and varied only the session's confidentiality. The projected
custody status changed with confidentiality alone: a bridge-readable session
lost its verified-custodial label. The implementation had derived custody from
who could read the session, which matched all its examples. Custody is sender
metadata in the trust model and is independent of session confidentiality.

# How to apply

- Derive which input actually authorises the output; hold it constant and vary
  a neighbouring property that should not affect it. This discriminates far
  more than adding cases that repeat the implementation's own decision table.
- Pair the targeted red with a valid neighbour, so the harness is shown to
  represent the supported path as well as the coupling.
- Rejected shortcut: deriving custody (or any assurance) from a transport or
  confidentiality property because one path made them coincide.

# Probe the neighbouring answer

The same discrimination applies when a change makes a client or service act
on an external answer (settle, forget, report ready). The author's tests
cover the intended answer; the defect hides in the answers next to it. Three
security reviews on 2026-11-13 each found their defect this way:

- **Same body, other status.** `aw` forgot a saved protected revoke whenever
  the body code was `applied_earlier`, under any status. A 403, 503 or 302
  carrying that body made it report "already applied" with nothing applied
  (NACK on 58734cb22). The fix settles only on a 409 with that code, through
  a sentinel error (0a0010c4c).
- **Other provider.** Readiness refused a replaced local custody key but not
  a switch from local custody to KMS, where every stored row is equally
  unreadable; a stand-in KMS client showed health ok (NACK on 824e6a299,
  fixed in 27e63dee6). The reviewer's suggested predicate would in turn have
  dropped the reverse, KMS-to-local, case; the author showed it and a
  mutation confirmed it.
- **An unguarded check.** A mutation removing a post-read fence check was
  caught by no test (d10a032f4); a test that catches it was added
  (6cdf5e3d6).

How to apply:

- For each decision the change takes on an external answer, list its
  neighbours: other statuses with the same body, the same body from an
  intermediary, the other provider, the other direction. Run one probe or
  mutation per neighbour before ACK.
- Report a suggested predicate fix only together with a mutation that shows
  what it would drop.

The [owner-binding decision](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
applies this separation to responsibility, membership, custody and consent.

Related: [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-p0-review` (note
`vary-independent-assurance-dimensions-in-review.md`; verdict e6e97ffd).

Probe-the-neighbour section: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/review-probe-the-neighbour.md. The review commits are source-reported.
