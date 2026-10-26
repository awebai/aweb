---
type: Lesson
title: Vary independent assurance dimensions in review
description: To test an assurance label, find the fact that should authorise it, hold that fact constant and vary a neighbouring property that should not matter; an implementation can match every example while deriving the label from the wrong fact.
tags: [lesson, review, trust-model, custody, testing]
timestamp: 2026-10-21
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

Related: [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-p0-review` (note
`vary-independent-assurance-dimensions-in-review.md`; verdict e6e97ffd).
