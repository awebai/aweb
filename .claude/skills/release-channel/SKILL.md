---
name: release-channel
description: Release @awebai/claude-channel. The release driver owns the sequence; this skill carries what the artifact is, the hazards that survive automation, and the one command. A tag push publishes NOTHING.
argument-hint: [version]
allowed-tools: Bash(make *), Bash(npm view *), Bash(git *), Bash(gh run *)
---

# Release @awebai/claude-channel

## The command

```
make release-plan
make release-run PLAN_ID=<id> PLAN_ARTIFACT_ID=<id>
```

The driver owns the whole sequence: it stages the package once, inspects the
exact bytes, refuses unless every guarantee holds, publishes those same bytes,
creates the tag, verifies what landed, and seals a receipt. There is no
hand-maintained step list here any more because the driver, not a human,
performs the steps.

## What you must know that the driver cannot tell you

**A tag push publishes nothing.** There is no tag-triggered publisher. The npm
lane (`.github/workflows/npm-release.yml`) is dispatch-only in three modes:
`stage-only` builds and inspects, `publish-continuation` publishes the exact
bytes a prior stage produced, `verify-only` re-inspects an already-released
version. A pushed tag runs no code at all. This is deliberate: a tag trigger
meant CI rebuilt from source and published whatever it happened to produce,
which is how five of six aw releases shipped wrong stamps.

**Publication is not delivery.** Three things must all happen before a user is
running the new code:

1. the exact bytes are published to npm,
2. the marketplace pointer in `awebai/claude-plugins`
   (`.claude-plugin/marketplace.json`) pins the new version — a forced pointer
   edge in `release/components.toml`, not an optional follow-up. Claude Code
   only re-resolves an npm source when the marketplace entry advertises a
   version, so publishing alone is invisible to existing installs,
3. each host updates the plugin **and restarts its session**. An installed
   plugin keeps its loaded code until restart; this is the `delivery_restart`
   obligation recorded in `release/components.toml`, and it requires proof per
   host, not an assumption.

Skipping step 3 is the most common way a "shipped" fix reaches nobody.

**Publication is immutable.** A published version is never overwritten,
deleted, or re-stamped, and a tag is never moved. If anything is wrong after
publication, fix forward to a new version.

**Pi ships separately.** If the same channel-core change is also in
`@awebai/pi`, that is its own lane, its own authorization, and its own delivery
proof — see the `release-pi` skill. Do not treat one publication as covering
both surfaces.

## Current gate state (delete this section when it stops being true)

The driver refuses a release whose runtime-contract edges have no measured
support. The channel↔server and pi↔server edges are not yet measured, so
`make release-run` will refuse these lanes until the G5 measurements land and
are anchored (epic `aweb-abbe`).

Until then a channel release requires an explicit, recorded exception, and the
G1 guarantees still hold in full — only the G5 orchestration is bypassed. The
precedent, including the exact authorization structure and the artifact
identities to adopt rather than rebuild, is recorded on `aweb-abbt`
(channel 1.7.2 / pi 0.3.2, 2026-08-05). Do not invent a new bypass shape; reuse
that one, and get the exception authorized rather than assumed.

## Verify what actually landed

```
npm view @awebai/claude-channel version
curl -s https://registry.npmjs.org/@awebai%2Fclaude-channel/-/claude-channel-<VERSION>.tgz | shasum -a 256
git ls-remote origin refs/tags/channel-v<VERSION>
```

The published tarball's sha256 must equal the staged digest the driver recorded,
and the tag must dereference to the exact reviewed source commit. Byte identity
is the point of the whole lane; check it rather than trusting that the workflow
said success.
