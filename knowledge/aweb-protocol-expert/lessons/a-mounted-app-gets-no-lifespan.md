---
type: Lesson
title: A mounted app gets no lifespan
description: Cloud mounts the OSS app as a sub-app, so a process service started in create_app's lifespan never runs in production Cloud while every OSS test stays green; a new lifespan service needs a public start/stop for mounting hosts, a loud signal when absent, and a Cloud change in the same pin.
tags: [lesson, asgi, lifespan, cloud, mounting, testing]
timestamp: 2026-11-04
---

Discovered on 2026-11-04 when the first bench against the Cloud app showed a
full snapshot per stream about every 16 s: the agent wake service that the OSS
lifespan starts was absent, and streams fell back to the slow path. Cloud
mounts the OSS app and copies its state at mount, and a mounted sub-app's
lifespan does not run. OSS tests run the lifespan, so they pass while
production Cloud would silently degrade (here, to 15 s wake latency).

# How to apply

A process-level service started in the OSS app's lifespan needs, in the same
change:

1. a public start and stop that a mounting host can call;
2. a loud signal when the service is absent (for example a one-time warning
   where it is first needed), so degradation is not silent;
3. the matching Cloud change in the same pin.

Bench or test against the Cloud app, not only the OSS app, before claiming the
service works in production. Related:
[the agent event stream is push-driven](/aweb-protocol-expert/decisions/agent-event-stream-is-push-driven.md),
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/mounted-subapp-gets-no-lifespan-state.md.
