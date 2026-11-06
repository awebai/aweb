---
type: Decision
title: Release candidates keep dependency floors
description: An RC tree carries >=X.Y.ZrcN floors and the final carries >=X.Y.Z, moved only for packages promoted in the same trees; exact pins were rejected because they couple independent releases. Release policy is proven at the real entry point with a really stamped tree.
tags: [decision, release, versioning, dependencies, rc]
timestamp: 2026-10-24
---

Chosen by the OSS coordinator on 2026-10-24 when release candidates became
mandatory before finals. Under PEP 440, `>=0.5.32` excludes `0.5.32rc1`, so an
RC tree whose floors named the final could not resolve its own prereleases.

# Decision

- RC trees carry `>=X.Y.ZrcN` floors and the final carries `>=X.Y.Z`. The
  promotion check allows a floor to move from RC to final only when the target
  package is promoted in the same compared trees; all other dependency metadata
  stays equal.
- The check proves source identity between RC and final, not qualification by
  a downstream consumer.

# Rejected

Exact pins between OSS packages: they would tie every independent registry
service release to a server release and invite resolution conflicts downstream.

# Proving release policy

Adding RC support to tag and registry publication did not make an RC-stamped
tree shippable. Artifact checks then failed on `rcN` versions; after those were
fixed, a running gateway read the RC registry version as below its stable
compatibility floor and its health check timed out, which looked like a crash
and was a live compatibility refusal. Separately, the promotion helper was
correct, but the ordinary tag workflow reached clone, sync, push and tag
without ever calling it.

- Run the actually stamped tree through the maintained artifact and integration
  stages, including the versions services report in health.
- Test the real workflow shell block on temporary repositories, intercepting
  its first external side effect, and create the real tags the workflow would
  check out.
- Keep a failing container's health body and both output streams;
  `docker logs ... 2>/dev/null` drops the container's stderr.

`docs/release.md` states the current rule; this records why floors and not pins,
and how the policy is proven.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-agent-activity` (notes
`rc-floor-promotion-preserves-dependency-policy.md`,
`rc-grammar-is-an-end-to-end-release-input.md`,
`check-release-policy-at-the-real-entry-point.md`,
`health-timeout-can-be-a-live-compatibility-refusal.md`; coordinator d528b5c8,
source review c93c1daf).
