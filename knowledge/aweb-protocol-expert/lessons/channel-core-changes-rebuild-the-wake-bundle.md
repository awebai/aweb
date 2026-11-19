---
type: Lesson
title: channel-core changes rebuild the wake runner bundle
description: aw wake runs a committed esbuild bundle of channel-core that every channel-core source change leaves stale while vitest, tsc, go test ./wake and make check-generated-copies all pass; run make test-wake-channel-core-bundle, which installs channel's pinned esbuild, before handing back any head that touches channel-core.
tags: [lesson, channel-core, aw-wake, build, verification]
timestamp: 2026-11-19
---

`cli/go/wake/channel_core_runner_bundle.mjs` is an esbuild bundle of
channel-core that `aw wake` runs. Any channel-core source change leaves it
stale, and an author's usual local loop does not say so: vitest and tsc pass,
`go test ./wake` passes against the stale bundle, and
`make check-generated-copies` (skills and docs) passes. Only
`scripts/check-wake-channel-core-bundle.sh` compares the bundle with the
source, and run bare it stops with "missing pinned esbuild" unless `npm ci`
has been run in `channel/`.

Why it matters: a head that changes verification in channel-core but not the
bundle would ship the old verification in the wake runner while every one of
those checks is green. In November 2026 the bundle was found stale for a
whole branch of channel-core commits and had to be rebuilt.

# How to apply

- After any channel-core source change, run `make test-wake-channel-core-bundle`
  (it depends on `test-node-deps`, so it installs the pinned esbuild, and it
  runs the check's self-test). Do not run the script bare.
- Rebuild with the script's `--write` and commit the bundle in its own commit.

# Elimination route

`make test` already includes `test-wake-channel-core-bundle`, so the full gate
catches a stale bundle. This lesson is for the author's local loop: a head
handed back as verified on the narrower checks above is not.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-19; notes/wake-bundle-staleness-is-a-separate-check.md. Verified by the harvester on aweb main (ecb9d825a): the Makefile target, its `test-node-deps` dependency, its place in `make test`, and the script's esbuild check.
