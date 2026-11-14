---
type: Decision
title: Every service the team bundle runs ships a published, digest-pinned image
description: A release publishes a digest-pinned image for every service the customer team bundle runs, because a deployment proof built on an image the release did not publish proves something customers cannot install; the protected signer therefore has its own image lane on the server tag.
tags: [decision, release, images, deployment, signer]
timestamp: 2026-11-14
---

Decided on 2026-11-14 when the protected signer gained its image lane (merged
to main in 7c10440a6).

# Decision

- Every service the customer team bundle runs gets a published image, and
  deployments pin it by digest from the publisher's readback receipt.
- A deployment or acceptance proof counts only when it runs those published,
  pinned images. A locally built image proves something customers cannot
  install.
- The protected signer is `ghcr.io/awebai/aweb-protected`. It is published by
  the same `server-v` tag, from the same tree and lock, as
  `ghcr.io/awebai/aweb-server`. Both images are built and checked before any
  registry access, so a failed build publishes neither.

How the lane is built and checked is documented in `docs/release.md`
("A server tag publishes two images"). That document is canonical for the
mechanism; this concept holds the rule and its reason.

# How to apply

- When a service is added to the team bundle, add its image lane to the
  release in the same change, and do not call it deployable before the lane
  has published.
- Release on one tag when two images must agree on source. A separate tag
  would let them drift apart.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14.
None of the proposal's named notes covers this claim. The harvester checked
the signer lane in `docs/release.md` and its merge on aweb main at 03f434b7c.
The native x86 and ARM build passes are source-reported.
