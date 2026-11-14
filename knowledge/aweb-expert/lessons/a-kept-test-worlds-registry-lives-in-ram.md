---
type: Lesson
title: A kept test world's registry lives in RAM
description: The team-deployment test world runs its registry database and Redis on tmpfs, so once a world is kept as a fixture, every namespace, identity, certificate and revocation dies with that container; back it up with a logical dump and never recreate it in an update.
tags: [lesson, test-worlds, registry, backup, deployment]
timestamp: 2026-11-14
---

`deploy/team/compose.test.yaml` runs `registry-db` with its data directory on
tmpfs, and `registry-redis` on tmpfs too, as "disposable ... gone with the
run". That is right for a throwaway journey. It stops being right when a
world is kept and becomes a fixture for later acceptance runs. This was found
on 2026-11-14 from the container metadata of a kept world.

In a kept world:
- namespaces, teams, identities, certificates and revocations exist only in
  that container's memory;
- stopping, restarting or recreating `registry-db`, restarting the daemon or
  rebooting the host erases them;
- rolling back an image cannot bring them back.

# How to apply

- A backup of a kept test world includes a logical dump of the registry
  database, not only the main volume. A backup across several servers needs
  [a detection fence](/aweb-expert/lessons/a-cross-server-backup-needs-a-detection-fence.md).
- A service update names only its target services, with `--no-deps`. Record
  the database containers' ids, `StartedAt` and config hashes before and
  after, and treat any change as data loss.
- A migration plan treats the registry as preserved data only when such a
  dump exists.

Elimination route: tooling that keeps a test world could refuse to recreate
its registry database, or could move that database to a volume. Neither
existed as of 2026-11-14.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14;
notes/run47-registry-is-tmpfs.md. The harvester checked the tmpfs mounts and
the "disposable" comment in `deploy/team/compose.test.yaml` on aweb main at
03f434b7c. The kept world's container metadata is source-reported.
