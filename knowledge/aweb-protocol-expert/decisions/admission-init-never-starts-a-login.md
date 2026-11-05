---
type: Decision
title: Admission init never starts its own login
description: aw init --admission-team-id never starts a device login; without a cli.team_admission login for its target host it refuses, naming the host and the exact aw auth login command, because unattended commands must not start interactive authorization and a login on a host the user did not choose is worse than a refusal. Decided, not yet landed.
tags: [decision, aw-cli, init, auth, admission]
timestamp: 2026-11-05
---

**Status:** decided on 2026-11-05 and implemented on a CLI branch for the
reply and admission-init fixes; not on main when recorded. On main, admission
init still offers to start a bounded device login.

# Decision

- `aw init --admission-team-id` uses an existing `cli.team_admission` login and
  never starts one.
- The target host is the first of `--aweb-url`, `--url`, `AWEB_URL` or
  `--server-name`.
- With no stored login for that host, init refuses, naming the host and the
  exact command: `aw auth login --scope cli.team_admission --server-name <host>`.
- A stored login for a different host is refused the same way, naming both
  hosts.
- When no host is named at all, the stored login is used and its own issuer
  is the host.

# Why

The problem this fixes was reported from OATS onboarding on aw 1.36.54. The
device login init started took its host from `--server-name` or the default
host, not from init's own `--aweb-url`, so a user pointing init at one host was
walked through authorizing another.

# Rejected alternative

Printing the host and continuing into the login. It keeps a surprise
interactive authorization inside a command that agents and scripts run
unattended, and any login init starts on a host it chose risks authorizing the
wrong host. A refusal that names the host and the command costs one explicit
step and cannot authorize the wrong place.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/admission-init-never-starts-a-login.md. Verified by the harvester on 2026-11-05: the refusal messages are on the branch, and main still prompts for a device login.
