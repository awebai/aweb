---
type: Lesson
title: The engine's builder still exports the image
description: On a Docker engine with the containerd image store, a plain docker build still exports layers and unpacks them into the store, taking about as long as the docker-container builder's export plus load, and FROM a large local image costs an extraction too; measure before choosing a builder to save time.
tags: [lesson, docker, containerd, gate, performance]
timestamp: 2026-11-25
---

It is tempting to build with the engine's own builder (the default builder,
docker driver) to avoid the export and load that the docker-container builder
needs. On an engine using the containerd image store that saving does not
exist: a plain `docker build` still exports the layers and unpacks them into
the store.

For the gate's unit image the plain build's export took 148.6 s, against
154.3 s for the docker-container builder's OCI export plus load. Starting
`FROM` a large local image also cost a layer extraction, 92 s for the gate
image.

# How to apply

- Do not pick a builder "to avoid export/load" on a containerd-store engine.
  Measure the image step's export, load and extraction times on the target
  engine before claiming a time saving.
- Count a large local base image as an extraction cost, not as free.

These are single measurements on one engine; repeat them before relying on
the exact numbers.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/engine-builder-still-exports.md. Unit image step times from gate runs
vm-cc7cf483 against vm-3501ee54. One run per observation.
