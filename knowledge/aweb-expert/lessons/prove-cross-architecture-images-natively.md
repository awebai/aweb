---
type: Lesson
title: Prove cross-architecture images natively, and qualify emulation from kernel state
description: An emulated arm64 probe on an x86 VM timed out where native ARM and x86 hosts passed on one archive, so cross-architecture image proofs run on a native host of each architecture; when emulation is used anyway, qualify it from the kernel's binfmt_misc entry and an aarch64 control, not from update-binfmts, which exits 2 on Ubuntu 24.04 while emulation works.
tags: [lesson, testing, gates, images, arm64, emulation, linux]
timestamp: 2026-11-13
---

Learned on 2026-11-12 and 13 while proving the server image for both
architectures from one archive on provider VMs.

- **Emulation is too slow to be the proof.** An arm64 import probe run under
  emulation on an x86 VM exceeded its timeout, which had been sized for native
  execution. The same archive then passed natively on an ARM host (CAX21) and
  an x86 host (CCX33). The emulated timeout said nothing about the image.
- **The management CLI is not the kernel.** On Ubuntu 24.04, qemu-user-static
  registers its handlers through systemd-binfmt. `update-binfmts --display`
  then exits 2 and lists nothing, while emulation works. A miss in that
  management database is not a verdict on emulation.

# How to apply

- Prove a multi-architecture image on a native host of each architecture,
  from the same archive. The procedure in `docs/release.md` (build once, move
  the archive with its hash, load the native variant on the ARM host) needs no
  emulated execution; keep it that way.
- If emulation must be used, qualify it from the effective state plus a
  functional control: `/proc/sys/fs/binfmt_misc/<name>` is enabled with flag
  `F`, and an arm64 container reports `aarch64`. Size any emulated bound from a
  measurement under emulation, never from native times.

Diagnosing from the CLI's report instead of the kernel state is the same
mistake as accepting a detector that was never shown to work:
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-18; notes/gate-lessons-2026-11-12.md (item 8). The emulated
timeout and the native pass on CAX21 and CCX33 are the source's report of runs
on 2026-11-12 and 13; the harvester did not rerun them. The native-ARM archive
procedure was read in `docs/release.md` on main at ecb9d825a.
