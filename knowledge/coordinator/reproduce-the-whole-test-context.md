---
type: Lesson
title: Reproduce the whole test context
description: A child command only reproduces a gate failure when its prerequisites, environment and boundary behavior match the failed run.
timestamp: 2026-10-01
---

Before extracting a failing command, identify the artifacts and environment
created by earlier targets. A test run without its prerequisite build can fail
for a different reason; a negative control without its activation variable can
go green without exercising the intended rejection. Preserve child output and
exit status, including unexpected setup failures, before disposable cleanup.

Environment and behavior must cross each runner boundary. Host context names or
port overrides are ineffective unless the container receives the required
endpoint and variables. Compose overlays must match the actual service set,
generated names must satisfy downstream validators, and subprocess fakes must
consume the input and implement the protocol their parent expects. Use explicit
framing rather than sleeps; draining to EOF is correct only where that caller
actually closes stdin.

The September release investigations included missing prerequisite frontend
builds, fake Docker output incompatible with an inherited manifest setting,
host-only Buildx contexts, and a provider fake racing its input pipe. An outage
test also stranded a stopped service after its first assertion failed. Restore
services in cleanup even on failure, and distinguish resulting cascades from
independent defects. Compare stable resource identities, not relative-age display
strings, when testing isolation.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `reproduction-must-preserve-build-state.md`, `retain-negative-control-child-output.md`, `provider-test-fixtures-must-consume-stdin.md`, `subprocess-fakes-must-cover-runner-environment.md`, `outage-tests-must-restore-service-before-asserting.md`, `test-port-overrides-must-cross-docker-boundary.md`, `compose-limits-match-base-services.md`, `generated-resource-names-must-match-consumers.md`, `buildx-contexts-across-runner-boundaries.md`, `buildx-cache-proof-relative-times.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
