---
type: Lesson
title: Database tests run only in a placed slot
description: Any test run that touches PostgreSQL or Redis, however few files, runs only in a slot placed by the OSS coordinator with its own private PostgreSQL and Redis; a teammate's request for RED/GREEN evidence does not grant one, and the host's PostgreSQL and Redis are never the place.
tags: [lesson, testing, environment, shared-host, postgres, redis]
timestamp: 2026-11-11
---

The team's operating rule, restated by the coordinator on 2026-11-11 after an
aweb-expert seat ran a focused RED/GREEN against the host's PostgreSQL and
Redis: focused database runs take a placed slot and a private PostgreSQL and
Redis, however few files there are. The seat read a teammate's "please give
RED/GREEN on that test" as permission to run. It is not: a request for evidence
leaves the means to the slot process.

# How to apply

- When evidence needs PostgreSQL or Redis, ask the OSS coordinator for a slot,
  or offer evidence that needs neither (a pure unit test, or a probe on code
  that does not touch the database).
- With a slot granted, the procedure is:
  - wait for the coordinator's GO;
  - claim the slot's marker directory atomically, with owner and head files;
  - start a disposable PostgreSQL and Redis labelled with your alias on random
    high ports;
  - run through the suite lock with `SUITE_LOCK_FOCUSED=1`, behind an invocation
    guard (gate open, load below 14, owner and head match, clean tree) and the
    egress guard;
  - send START and END mail;
  - before removing anything, query by label and remove only your own
    containers and marker.
- After a mistaken host run, check the host PostgreSQL for new databases and the
  host Redis for keys from that time window, and report what you found,
  including a correction of any earlier wrong attribution.

Related: [focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md)
says what a focused run must include; this lesson says where it may run.
[Never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md)
is another hazard of agents sharing one host.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-11;
notes/focused-pg-runs-need-a-slot.md. The rule is the coordinator's,
source-reported; the source's later focused runs followed the procedure.
