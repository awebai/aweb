---
type: Lesson
title: A limiter fixture keyed on a shared front throttles everyone behind it
description: When the registry's rate limiter keys on the address of the front that proxies it, filling a window throttles every client of the registry, the app servers included; before using such a fixture, list every call the act under test makes across that front, and identify the proxy from the retained configuration, not from container names.
tags: [lesson, testing, e2e, rate-limiting, registry, fixtures]
timestamp: 2026-11-13
---

Observed on 2026-11-13 in the team-deployment journey (run46). The journey
filled the registry limiter's `did_key` window to test that a protected act
waits out a throttle on its signing path. The act failed earlier, in a call
the fixture's design had not considered.

# What happened

Every registry read in the deployment passes through one front, and the
limiter keys on the address of that proxying front, not on the original
client. Filling the window therefore throttled every client of the registry
at once, including the aweb server. Before a protected human-role act
prepares, aw asks aweb for the app's installation, and answering that needs
aweb to resolve the member's key through the registry. The logs showed the
registry's 429s, then aweb's `RegistryThrottled` warnings with a 53 s hint,
then four 503 answers to the installation lookup. On aweb main at dfce11678,
the server answers that case 503 with no `Retry-After`, and aw maps every
non-404 failure of the lookup to `app_installation_unavailable` without
waiting. The limiter design had covered waiting only on the signer path.

This is not a fixture budget problem: making the window larger or shorter
would hide the call that is not throttle-aware. The fix to the callers belongs
to their owners.

# How to apply

- Before using a limiter fixture keyed on a shared front, list every call the
  act under test makes across that front, directly or through a server it
  calls, not only the call being tested. Each one is under the limiter.
- Identify the proxy and the limiter key from the retained configuration (the
  front's address and its Caddyfile), never from container names.
- Read a failure under such a fixture by its first throttled call, not by the
  step the test was aimed at.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/throttled-lookups-outside-the-signer-path.md. The harvester read the
server's identity-binding adapter and aw's installation lookup on aweb main at
4b478bba5 and found the behaviour described. The run46 log sequence is
source-reported; the source reports that the gate reviewer independently
supported the association.
