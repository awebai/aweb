---
type: Decision
title: candidate-gate/ stays at the repository root
description: candidate-gate/ is not moved out of the aweb root, because vm-gate reads its Dockerfile at historical SHAs; revisit only if vm-gate stops reading gate files from history.
tags: [decision, repository-layout, vm-gate, gate]
timestamp: 2026-11-27
---

Decided by the OSS coordinator on 2026-11-27, during a tidy of the aweb root.
The coordinator chose option (c) of three.

# Decision

`candidate-gate/` stays at the aweb repository root. A tidy does not propose
moving it.

# Why

vm-gate reads `candidate-gate/Dockerfile` with `git show <sha>:...` for every
SHA it admits (`scripts/vm-gate/vm_gate/source.py`, `cli.py` and `project.py`
at aweb 39b3f09114). Those SHAs include the aweb source SHA a hosted release
pins, which always predates a move. So a move has two costs. It needs
compatibility code that lasts as long as any supported pin predates the move,
or the gate refuses those SHAs. Either cost outweighs removing one clearly
named root entry.

# Rejected

- **(a) Path-by-SHA fallback code** in vm-gate: a compatibility shim that
  lives as long as any supported pin predates the move.
- **(b) Accepting that vm-gate refuses every SHA from before the move**,
  including the aweb source a hosted release pins.

# Revisit

Only if vm-gate stops reading gate files at historical SHAs. The same test
applies to any path a gate reads from git history; see
[a path move's in-repo check asks which revision each reader reads](/aweb-expert/lessons/a-path-move-check-asks-which-revision-each-reader-reads.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-root-tidy, 2026-11-27;
notes/candidate-gate-stays-at-root.md. The coordinator's ruling is
source-reported. The vm-gate reads were checked at aweb 39b3f09114 and at main
90519b0d2.
