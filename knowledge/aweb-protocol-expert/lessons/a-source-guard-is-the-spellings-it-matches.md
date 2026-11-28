---
type: Lesson
title: A source guard is the spellings it matches
description: When a design or review names a lint or AST guard as a contract's protection, state which spellings it matches and what it does not resolve (aliases, wrapper types, values passed through an allowed type, data flow); the contract stays review of what enters the signer and what a return contains, and a guard is called sufficient only after an alias fixture has been run against it.
tags: [lesson, review, design, custody, lint]
timestamp: 2026-11-27
---

A hosted key-custody design protected its signing boundary with a source
guard: an AST check over type annotations, meant to keep key material from
leaving the signer. The builder offered it as "annotation rules instead of
data flow, stricter", and the design took that wording in as a property of
the boundary. Review returned it. An ordinary type alias of `bytes` passed the
guard as built, although the guard's own fixtures were green. The design was
revised to call the guard a spelling check that resolves no aliases and
follows no values, and that revision was accepted.

A syntactic rule is only as strong as the spellings it lists. An alias, a
wrapper type or a value passed through an allowed type gets past it, and so
does anything that only data flow would show. The real cost of the "stricter"
wording is what it switches off: once the document says the guard covers the
entry points, nobody reviews them.

# How to apply

- When a design or review names a lint or AST guard as protection for a
  contract, write down exactly what it matches (which names, annotations or
  call shapes) and what it does not resolve: aliases, wrapper types, values
  carried through an allowed type, data flow.
- Keep the contract as review of what enters the signer and what each return
  contains. The guard helps keep callers at that gate; it does not replace
  reviewing the gate.
- Before calling a guard sufficient, run it against an alias fixture (and a
  wrapper fixture) as well as its own cases. A guard that stays green on them
  is a spelling check, and the document must say so.
- Treat "stricter than a flow check" as a claim to test, never as a property
  to record.

The gate itself is [gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md);
running a guard against an alias it should catch is a case of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

Observed once, on one design.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/describe-a-source-check-as-what-it-matches.md.
