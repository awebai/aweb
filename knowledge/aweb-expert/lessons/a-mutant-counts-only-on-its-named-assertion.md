---
type: Lesson
title: A mutant counts only on its named assertion, in an artifact built the production way
description: A mutation self-test counts a negative only when the guarding test, run alone, fails with ERR_ASSERTION on its own named message, against a mutant built by the package's own production build; pair each negative with a valid fixture through the same export, report every other failure as inconclusive, and show the runner itself refuses a harmless mutant and a wrong expected message.
tags: [lesson, testing, mutation, verification, self-test, typescript]
timestamp: 2026-11-27
---

Learned on 2026-11-27, rewriting the TypeScript dist self-test for the Pi
extension and channel bundles. The old self-test mutated source and required a
checker to fail by finding a marker string in the bundle. That proves the
string survives bundling, not that the behaviour does. The reviewer's design
ACK set the requirements below.

# Why a red is not enough

An always-red self-test is as untrustworthy as an always-green one. A mutant
that fails on an import error, a build error, or a fixture the export rejects
for some other reason looks exactly like a real negative unless the runner
names the assertion that failed. A mutant built by a hand-written build line
is another artifact than the one shipped: here the hand-written esbuild line
lacked the production banner.

# How to apply

- **Test the behaviour against the built bundle**, not a marker in it.
- **Pair each negative with a valid fixture through the same export.** The
  valid case shows the export accepts good input, so the negative's failure
  comes from the defect, not from the fixture.
- **Run only the guarding test** (for node:test, `--test-name-pattern` with
  the TAP reporter). Count it as a negative only when exactly that test fails
  with `code: 'ERR_ASSERTION'` and the assertion's own message. Anything else
  is INCONCLUSIVE, never a pass.
- **Build the mutant the production way.** Mirror the package layout in a
  temporary tree and run the package's own build (prebuild and provenance
  included), with the sibling dependency pointing at the mutated copy.
  A provenance check that requires dependencies inside the sibling's own
  `node_modules` refuses a symlinked one: copy that directory, link the rest.
- **Show the runner can fail.** On throwaway copies, a harmless mutant must
  give SELF-TEST FAIL and a wrong expected message must give INCONCLUSIVE.

This applies [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
(a red counts only if it names the property) to an automated mutation runner,
and [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
to how the mutant is built.

# Elimination route

The rules are encoded in the self-test runner itself
(`scripts/test-typescript-dist-freshness.sh` at 3686733463, on the E8.1
follow-up branch, not yet on main). This lesson is for writing or reviewing
another marker-grep or text-mutation self-test.

# Limits

One self-test (the Pi extension and channel bundles), not yet reviewed at
SHA level.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/a-mutant-counts-only-on-its-named-assertion.md. The harvester read
commit 3686733463 ("TypeScript dist self-test: guarded behaviours fail their
own assertions"): it runs the single named test with the TAP reporter and
reports INCONCLUSIVE unless the output carries `ERR_ASSERTION` and the
assertion text. The reviewer's ACK, the six mutants, the two runner controls
and the banner and symlink findings are source-reported.
