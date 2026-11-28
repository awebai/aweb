---
type: Lesson
title: A leaking text scan becomes an allowlist of known forms
description: When a checker infers facts from a free-form language (Dockerfile RUN text, shell, YAML run blocks) and review keeps finding shapes it misreads, stop widening the scan; accept exactly the forms in use, refuse any other form in command position as an unsupported recipe form, and ignore mere mentions.
tags: [lesson, review, checkers, release, parsing]
timestamp: 2026-11-27
---

A release checker had to find the Go toolchain each container image builds
with. Each review round widened the scan: any mention of a version, then
`FROM` plus `ARG`, then the download URL, then `RUN` text only with comments
dropped. Each round the reviewer found the next shape it misread: a stale
`ARG`, an `echo` of the expected version, a comment holding a URL, an
installer quoted as an `echo` argument. Five review rounds each closed one
shape and left the question open for the next `RUN` line. A general scan of a
free-form language is never finished.

The coordinator's direction ended it, and the checker landed and was ACKed
that way:

- Keep an allowlist of whole-instruction patterns for the forms the audited
  recipes actually use (here, one installer form and one `GOVERSION` check).
- Any Go install or check **in command position** that matches no pattern is
  refused as "unsupported recipe form", naming the file.
- Everything else, including mentions in comments, echoes and strings, is
  ignored rather than interpreted.

Adding a recipe form then costs one pattern and its test. That cost is
intended: a new form is a change someone should look at, and the refusal
makes sure they do.

# How to apply

- When a checker's job is to read facts out of shell, Dockerfiles or CI run
  blocks, do not parse the language in general. Enumerate the forms in use,
  accept exactly those, and turn an unknown form into a refusal, never a
  guess.
- Distinguish command position from mention: only an instruction that would
  run is evidence; text that merely contains the token is not.
- Treat a second review round on the same inference as the signal to switch.
  Widening the scan again buys one more shape, not an end to the loop.
- A refusal is only evidence once shown: give each refused shape a test that
  reds if the checker starts accepting it
  ([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

The same review also had to fix what the scan compared against; that is
[an expected value comes from the declaration](/aweb-expert/lessons/an-expected-value-comes-from-the-declaration.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/allowlist-known-forms-over-widening-a-scan.md. Review rounds 1863b3e7,
cd3638b8, 169de8f9 and fd11a18d; coordinator direction ba92680f; landed as
367f3f367f (on the contracts task branch at harvest time) and ACKed in
73f90e1e.
