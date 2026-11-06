---
type: Lesson
title: An npm tarball publish records no gitHead
description: npm pack never writes gitHead and npm publish of a tarball fills it only when npm's cache sits inside a git repository, so aw publishers write the source commit into every package.json themselves; a test whose npm cache is inside its fixture repository gets a gitHead for free and cannot catch the regression, and releases already published without one resolve their source from the awebai/aw tag.
tags: [lesson, release, npm, provenance, aw-cli, testing]
timestamp: 2026-11-06
---

aw 1.36.55 reached npm with no `gitHead`. Nothing failed: the publishers had
moved to packing each package once and publishing the tarball, and npm stopped
recording the source commit without a word. The decision that followed (both
aw publishers write the stamped commit into each `package.json` before packing,
and readback refuses a missing or different registry `gitHead` permanently) is
recorded in `docs/release.md` and `cli/go/npm/publish.sh`. This concept records
why npm cannot be trusted with the field, which the repository states only as a
conclusion.

# What npm does (measured on npm 11.20)

- `npm pack` never writes `gitHead`, whether the package sits at a git
  repository's root or nested in it, clean or dirty. A `gitHead` already present
  in `package.json` is kept verbatim.
- `npm publish <tarball>` unpacks the manifest under npm's cache and fills a
  missing `gitHead` from the git repository that contains **that cache
  directory**, not the source checkout. On a release runner the cache is outside
  the checkout, so nothing is filled.

# How to apply

- Never rely on npm to fill `gitHead`. Relying on it was rejected: whether the
  field appears depends on where npm's cache lives, not on what is published.
- A publisher test must keep `NPM_CONFIG_CACHE` **outside** its fixture
  repository, as on a runner. With the cache inside it, npm fills `gitHead`
  and the test passes even when the publisher writes none.
- For a version already published without `gitHead`, resolve its source from
  the awebai/aw distribution tag: the peeled commit `v<version>^{}` equals the
  commit stamped into the binary (checked for 1.36.54, where both sources exist,
  and 1.36.55, whose tag commit equals its binary stamp). Use the tag only when
  every package lacks `gitHead`, and still check the binary stamp.

aweb-cloud's lesson on reviewing pins against published artifacts says what to
check in a published package; this concept explains why the field can be
missing.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/npm-tarball-publish-githead.md. The harvester checked the publisher, readback and tag-fallback code against aweb main at 07f1c8f0c (fix 86af2e122).
