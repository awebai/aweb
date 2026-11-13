---
type: Lesson
title: A rename-replaced credential mounts by directory, and the receiver decides where secrets live
description: OATS's login receiver installs a harness token by atomic rename and refuses non-root-owned or writable ancestors, so a team deployment binds the login directory, never the token file, and keeps its secrets directory in a root-owned tree rather than under an operator's home.
tags: [lesson, deployment, credentials, docker, oats]
timestamp: 2026-11-13
---

Learned on 2026-11-13 while placing the OATS login receiver for a team
deployment's real-agent proof. Both traps are invisible until a rotated token
never arrives or the receiver refuses at install time.

- **A single-file bind mount pins the old inode.** The container keeps
  reading the inode it saw at start. A writer that replaces the file by
  rename(2), as the receiver does for atomicity, leaves the container on the
  old credential forever. Mount the containing directory. The team bundle
  already mounts its login directory (`<secretsDir>/agents`) this way; keep it
  so.
- **The receiver's ancestor check decides the host layout.**
  `oats-login-receive` (OATS 0.69.19) refuses any ancestor of its target that
  is not root-owned or is group- or other-writable, and writes only to a
  root-configured path. A run tree under an operator's home therefore cannot
  host the login directory. The placement that fits without bundle changes is
  a `compose.secretsDir` in a root-owned tree, such as
  `/srv/oats-team/<team>/secrets` (root, 0755), with per-component
  subdirectories pre-created for the staging user and the receiver path
  pointing at `secrets/agents/<harness>-token` inside it.
- **Reaching the host.** The receiver host needs only python3.
  `oats server add --ssh` names the OATS inside the agent container; only the
  operator route (`--operator-ssh`) reaches the host's root forced command.

# Status

Read from the OATS 0.69.19 receiver source (parent creation, the root-owned,
not-writable ancestor check and the rename install) and the OATS server docs,
and confirmed by the OATS expert (11a28a96). As of 2026-11-13 it had not yet
been installed or exercised on a host.

# Elimination route

The single-file mount trap is one a teamctl wiring test asserting a directory
mount for the login credential would eliminate; until such a test exists, this
lesson is the guard.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13; notes/credential-files-mount-by-directory.md.
