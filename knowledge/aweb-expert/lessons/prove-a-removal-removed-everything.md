---
type: Lesson
title: Prove a removal removed everything
description: A removal's zero-reference grep proof passes silently when its search cannot match (macOS git grep -E ignores \b), when frozen files are edited to make it pass instead of being listed as exceptions, and when orphaned code still compiles; use git grep -P or a known hit, name each immutable exception by path and reason, and diff dead-code reports against the pre-removal commit.
tags: [lesson, removal, verification, grep, go, deadcode]
timestamp: 2026-11-27
---

Juan's rule for removals is that a removal removes everything, with a grep
proof of zero references except the CHANGELOG. The proof is evidence of
absence, so it fails in the direction that hides what it is looking for. The
E1 (b) and E1 (c) removals in November 2026 met three ways it does.

# The search must be able to match

On macOS, `git grep -E` uses POSIX ERE, which does not support `\b`. A
pattern alternative written with `\b` matches nothing, there is no error, and
the output looks the same as a clean result. The E1 (b) proof was sent as
clean on an `-E` run. Rerun with `git grep -P`, it found
`docs/vectors/README.md` still naming the removed status document.

- Write the proof with `git grep -P` whenever the pattern uses `\b`, `\w` or
  other Perl classes.
- Before trusting a zero, show the pattern matches: run it on the
  pre-removal commit, or on a file known to contain a hit. This is the general
  rule of [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md),
  applied to grep.
- Phrase greps such as `team admin add` miss tests that run the built binary
  with the command as separate argv strings (`"team", "admin", "add"`).
  Search for the argv form too.

Observed with Apple git only; GNU builds may differ, which is one more reason
to show the pattern matches rather than rely on the flag.

# Immutable references are listed, not edited

Some references are correct to keep, and the proof names each by path and
reason instead of editing it to make the grep come out empty:

- applied migrations that create the dropped tables. Migrations are never
  edited, so a new migration drops the tables and the old files keep naming
  them;
- frozen vectors and their packaged copies (the hook catalog lists the removed
  event as excluded);
- frozen copies of applications;
- accepted knowledge in `knowledge/`.

Sort every hit as edit or immutable before handback. Generated copies are not
immutable: regenerate them from the built binary or their script. An
inventory exemption entry for a removed call is not immutable either; the
identity inventories fail on an exemption with no call left.

# Orphans are found by diffing dead-code reports

After the obvious files were gone in E1 (c), build and vet passed, but the
removal had left nine functions with no caller, five production functions
reachable only from their own tests, and an unused const. None broke the
build. What found them:

- run `deadcode -test ./...`, `deadcode ./...` (production code reachable
  only from tests) and `staticcheck -checks U1000 ./...` on a `git archive`
  export of the pre-removal commit and on the tree;
- keep only the lines that are new, since the tree already carried some
  pre-existing unused symbols;
- repeat after each deletion, because removing one orphan orphans the next,
  until nothing new appears.

This was run against `cli/go` only. Server and TypeScript packages need their
own equivalent.

# Elimination route

The first and third traps could become a checked script, a removal proof
that refuses an `-E` pattern containing `\b` and prints the dead-code diff.
Until one exists, this lesson is the rule.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-27;
notes/git-grep-ere-has-no-word-boundary.md,
notes/removal-grep-proof-has-immutable-exceptions.md and
notes/removal-finds-orphans-by-diffing-dead-code.md. Checked by the harvester:
commits c59639f477 (the line the `-E` proof missed, with the `-P` rerun),
b57d0468c9 (the exceptions list) and 626dd73e7d (the orphans found by the
dead-code diff) on the E1 removal branches, not yet on main at 90519b0d2;
`git grep -E 'clone\b'` returned nothing and `git grep -P 'clone\b'` a hit on
Apple git 2.54.
