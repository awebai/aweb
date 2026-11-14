---
type: Lesson
title: Compose checks every service's env_file when any service starts
description: Newer Docker Compose fails to start any service while another service's env_file in the active profiles is missing, so an end-to-end lane writes static env files before its first up and declares files that only exist later as required false, never as placeholders.
tags: [lesson, testing, e2e, docker, compose, gate]
timestamp: 2026-11-14
---

On 2026-11-14 both naapp/secrets end-to-end fixtures failed on a gate VM at
`up dns`, before any test ran, because `secrets.env` was missing. The lanes
wrote `secrets.env` only when the apps started and `protected.env` only once
the signer was configured. The gate VM's Compose validates the `env_file` of
every service in the active profiles, not only the services being started. An
older Compose on the developer machine did not, so the lanes passed locally
and the owner-acts lane carried the same latent defect.

# What to do

- Write a file whose content is static before the lane's first `up`.
- Declare a file that can only exist later with the long form
  `env_file: [{path: ..., required: false}]`, as the `deploy/team` compose
  files already do.
- Never write placeholder values to satisfy the check; the proposal reports
  that the gate refused that fix.
- A service that does start without its file must still fail loudly on its own
  missing settings.

A lane green on a developer machine is not evidence that it starts under the
gate's Compose; see
[reproduce the whole test context](/coordinator/reproduce-the-whole-test-context.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-14;
notes/compose-checks-every-env-file.md (task aweb-adbb; gate run at 7469bbb3).
Fixed on aweb main at becd164dd.
