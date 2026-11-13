---
type: Lesson
title: A served credential snapshot is fenced by every observation
description: A server that reloads credentials rewritten in place must order admissions by when each capture read the home, fence on every observation including refusals and failed builds, sign only with the admitted snapshot, publish on recovery even with nothing left to write, and preflight scratch directories that hold key copies.
tags: [lesson, concurrency, custody, security, review]
timestamp: 2026-11-13
---

Learned on 2026-11-13 building in-place credential updates for
`aw custody serve` (see
[custody detects every credential writer](/aweb-expert/decisions/custody-detects-every-credential-writer.md)).
"Never serve superseded credentials" needed each of the fences below. Each
was missed once and found by an independent review probe.

# The fences

1. **Order by when a capture read the home, not by when it reached the
   decision.** Captures and builds run outside the decision mutex so a
   network build does not serialise admissions. A capture that read the home
   before a refused one can therefore reach the decision after it. Take an
   order ticket under the shared credential lock just before the read, and
   refuse or discard anything older than the newest refusal. A stamp taken at
   decision time was the first fix, and both reviewers independently found
   the gap in it.
2. **Fence on every observation, not only on successful attachments.** If the
   generation advances only when a build succeeds, a delayed older capture
   can be built and served after a newer build failed. If a refusal drops the
   snapshot before checking its own generation, a delayed older refusal drops
   a newer healthy snapshot. Record the newest generation observed on every
   admitted capture, refusal and failed build; a build that finishes after a
   later refusal is discarded.
3. **Every signer uses the admitted snapshot, never the live home.** The
   first review checked only the client constructor; the app-signing path
   reloaded the live home's team certificate at signing time, pairing an old
   client with a new credential. Carry the certificate in the admitted
   dependencies and fail rather than fall back to the home.
4. **Exact-operation recovery publishes even when nothing is left to write.**
   A retry of an interrupted update may find every file already written. It
   must still publish the generation and clear the marker, or the home stays
   "incomplete" forever.
5. **Private scratch that holds key copies is a path-safety surface.** A
   capture directory under the home must pass the strict private-directory
   preflight (no symlink) before and after it is created, before key bytes
   are written; otherwise a symlinked capture root exports the key.

# How to apply

When reviewing any reload-in-place feature, probe a delayed old capture
against a newer refusal and against a newer failed build, and grep every
signer and credential consumer, not just the client constructor. Keep the
probes as tests, as was done here.

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/snapshot-admission-must-fence-every-observation.md. The fixes are on
main: ee9143a72 (no superseded snapshot), 92a10266c (monotonic admission,
admitted-certificate app signing, recovery publishing, capture-root symlink
preflight) and e53f14e51 (capture-order refusals, with the reviewers'
delayed-capture probe kept as a test). The review NACKs and ACKs are the
source's report.
