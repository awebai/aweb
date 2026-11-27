---
type: Lesson
title: A freeze rule names both sides of its comparison
description: Write every freeze or fence condition as "X from source A differs from Y from source B"; a rule such as "the generation is current, any difference freezes" lets a faithful builder freeze on benign local staleness while the real takeover check gets no input.
tags: [lesson, authority, design, review, custody]
timestamp: 2026-11-27
---

Two different differences look alike in a design sentence, and they need
opposite answers:

- **Network versus record.** The registry or DNS now says something other than
  what we recorded: the controller, the epoch, the team key. That is a takeover
  signal, and the answer is to freeze.
- **Record versus record.** One of our own rows was prepared against an older
  state of another of our own rows, for example a journal row prepared before a
  legitimate promotion of our key. That is a stale preparation, and the answer
  is to refuse and re-prepare, not to freeze.

A hosted custody design said the key row's generation must be "current" and
that any difference freezes, without saying current against what. The builder
transcribed it faithfully as prepared-generation versus local-generation. That
froze a whole organisation on a benign stale preparation. The gate's evidence
also carried no network team key, so the takeover the rule was meant to catch
had no input at all. Review caught both halves, and the design was corrected
before any implementation ran.

# How to apply

- Write each freeze or fence rule as "X (source) differs from Y (source)", and
  say which kind of difference it is: takeover (freeze) or stale local
  preparation (refuse and re-prepare).
- Name the evidence field that carries the network side.
- Check that the gate's input type actually has that field. A rule whose input
  is missing is not implemented, however green its tests are.
- When reviewing a builder's gate, read which two values it compares, not only
  that it compares something.

When the network side is fetched outside the locks that guard the record side,
the record can also move during the wait; see
[network evidence carries the basis it is compared with](/aweb-protocol-expert/lessons/evidence-carries-the-basis-it-is-compared-with.md).

# Status

Design-level only: the corrected design was reviewed and accepted, but no
implementation has run this gate yet.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/freeze-condition-must-name-both-sides.md.
The design is hosted, so it is described generically here; its document and
commits are not cited.
