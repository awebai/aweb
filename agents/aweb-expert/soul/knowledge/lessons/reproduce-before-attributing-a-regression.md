---
type: Lesson
title: Reproduce and read the first error before attributing a regression
description: A bisect bounds the delta that broke something, not the commit; reproduce with artefacts retained, read the literal first failure rather than the cascade, and raise the bar when the suspected code is your own.
tags: [lesson, debugging, release]
timestamp: 2026-06-30
---

Recorded by the OSS coordinator role on 2026-06-30. A launch-critical end-to-end
regression was bisected correctly to a release delta and attributed by name to
the coordinator's own commits because they touched the same area. The
coordinator found a real but latent coupling in that code and was about to ship
a fix for it. Reproducing with kept logs showed the first failure was an
unrelated guard from a different commit; a four-line harness adaptation fixed
the run, and the suspected commits were exonerated.

# How to apply

- A bisect bounds the delta. It does not name the commit. Do not push a fix on a
  by-name suspect; get the actual failing command and error string.
- Reproduce with artefacts retained and read the first failure, not the cascade.
- When the suspect is your own code, raise the bar rather than lower it;
  confirmation bias makes blame feel right.
- A real-but-latent flaw found while hunting is worth tracking and is not
  automatically the regression. Keep them distinct.
