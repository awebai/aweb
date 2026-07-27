# Verification method — earned during default-aajc, 2026-07-26

The `aajc` epic and the two reviews stacked on it found a handful of real code
defects. In the same period the team found **nine failures in its own measuring
instruments**. Every one would have produced a confident wrong answer. None was
caught by inspection — only by testing the instrument against a known case.

This is the durable output of that epic. It matters more than any individual fix.

## The rules

**A red is evidence only if its failure text names the property.** Environmental
failures present as timeouts, connection errors and killed processes — they
cannot produce a property-naming assertion. Quote the assertion text in handoffs,
never a pass/fail count. Corollary: "contention causes spurious failures so
greens stand" **inverts** for mutation testing, where the red *is* the positive
result.

**A zero is evidence only if the detector was shown positive** — on the *actual*
pattern (not merely proving the pipeline runs), **repeatably** (a search can
match its own command line and flip between invocations), and in a **separate
invocation** (a control in the same invocation puts the literal into the
searcher's argv, where the measurement then finds it). Read raw output, not
counts.

**A validated detector is not a valid experiment.** A passing control proves the
instrument can *see*; it says nothing about whether the harness can *produce* the
condition. Only removing the fix separates them. A harness that cannot go red
when the fix is gone is measuring something else, however well built its
detector. This is the hardest of the family: there is no visible defect.

**Which control you need depends on which way the claim points.** Absence claim
(no caller does X, no orphans remain) → **known-positive**, catches blindness.
Presence claim (the marker landed, all eight ran, the SHA is on the remote) →
**known-negative**, catches looseness. The opposite control protects nothing. If
one check reports several values, ask the direction question of *each*.

**A partial red is evidence, not a failure to reproduce.** The assertions that
*don't* red show the mutation was targeted. Widening it until everything reds
destroys the information.

**Classify every non-red, predicting the sensitivity set first.**
Expected-insensitive → the mutation was targeted. **Expected-sensitive but
passed → a vacuous guard**, found free. Predicting first is what makes the
classification honest rather than rationalisation.

**The harnesses most likely to be missing all of this are the ones that are not
tests** — log greps, process counts, exit-code checks, delivery read-backs,
roster queries. Mutation practice covers real tests automatically, so compliance
there is invisible; everything else sits outside it.

## Review standard now in force

Any verdict citing a harness must carry one of two lines: *"the fix was removed
and it redded, at these assertions"* or *"I did not check whether this harness
can fail."* Either is acceptable. Silence is not.

A required line beats a habit: writing it forces you to name **which** harness,
and naming it is when you notice it isn't the one you tested.

## Why any of it was found

Each person caught the previous person's blind spot — not by being individually
careful. It worked because nobody defended a first answer, including when the
first answer was the coordinator's, which it often was.

The single sentence worth keeping, from `aw-sec-dev-16`: *nothing in the review
process was shaped to ask whether a guard fires, because it passed, and passing
is what we check for.* That is why sixteen vacuous guards survived a full audit.
