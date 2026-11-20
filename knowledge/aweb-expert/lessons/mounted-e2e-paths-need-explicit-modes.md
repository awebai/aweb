---
type: Lesson
title: Mounted e2e paths need explicit modes under a private umask
description: Gate VMs launch with umask 077, so mkdir(mode=0o755) makes 0700 directories and write_text makes 0600 files; every public directory or file an e2e lane mounts into a non-root service needs an explicit chmod, while private material gets its strict owner and mode from a root provisioning step.
tags: [lesson, e2e, gate, testing, permissions]
timestamp: 2026-11-14
---

The gate VMs launch lanes under a private umask, 077. Python's
`Path.mkdir(mode=0o755)` applies `mode & ~umask`, so it creates a 0700
directory there, and `write_text` creates a 0600 file. A bind mount keeps the
host's owner and mode. A container that runs as a non-root user other than the
launching user then cannot enter the directory or read the file.

Developer machines usually run with umask 022, where the same lane passes. On
the gate the failure surfaces far from its cause, as an apparently unrelated
error. On 2026-11-14, in one series of gate VM runs:

- CoreDNS, which runs as nonroot, exited because its DNS directory was 0700.
  This hit the team deployment journey and both Secrets lanes.
- Logs could not read its mounted database URL, because its files directory
  was 0700.
- The signer's operator bootstrap failed with only the generic
  `protected_operator_failed`. Its secrets directory was 0700 and owned by the
  launching user, while the files inside were correctly 0400 and owned by the
  signer's uid.

In each case the lane had already set its files to 0644, or chowned them to
the service, but left the directory to the umask.

# How to apply

- Give every public directory a lane mounts into a service an explicit
  `chmod(0o755)` after creating it, and every public file an explicit
  `chmod(0o644)`. A file that is replaced atomically needs its temporary file
  chmod-ed before the rename.
- Private material (keys, custody, credentials) keeps its strict owner and
  mode. A root provisioning step chowns it to the service's uid, and the
  directory that holds it is still made traversable for that uid.
- Never change the launch umask, or write placeholders, to make a run pass.
- When auditing a lane before a gate run, grep its mounted paths for
  `mkdir(` and `write_text(`. Running the lane locally under `umask 077`
  reproduces the gate's condition.
- When a non-root service fails on the gate but not locally, check the modes
  of its mounts before investigating the error it reports.

The fixes so far are per-site chmods. A shared helper that creates mounted
public paths with explicit modes would turn this lesson into code.

The converse rule for credentials, that the directories receiving staged
secrets must be private before the first write, is a separate concern: this
lesson is about public mounts that must stay readable.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-14;
notes/e2e-modes-under-private-umask.md (task aweb-adbb, gate VM runs). The
fixes are e9dc7a77f, 04f1f6be1, 4b71ded55 and 359233875 on branch
agents/aweb-expert-owner-acts-signer-deploy; the harvester confirmed they add
the explicit chmods and that the branch had not landed on main at 924c30584.
