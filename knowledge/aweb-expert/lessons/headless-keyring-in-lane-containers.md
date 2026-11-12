---
type: Lesson
title: A headless gnome-keyring in a lane container keeps its files and sockets off host bind mounts
description: aw's human-key commands store keys through the Secret Service; in a container the keyring needs stdin for its unlock password, its data and runtime directories on the container's own filesystem, IPC_LOCK, and on Linux a host-uid user with a passwd entry, because bind mounts enforce ownership there and Docker Desktop hides it.
tags: [lesson, testing, containers, keyring, linux, docker]
timestamp: 2026-11-12
---

aw's `id human init` stores the human key through the Secret Service
(go-keyring). In the owner-acts round-trip lane it failed for several
independent reasons. Each one looked like an aw failure.

- **No stdin, no default collection.** `docker exec` without `-i` passes no
  stdin. `gnome-keyring-daemon --unlock` then reads no password, and the
  Secret Service has no default collection (alias `/`).
- **A macOS bind mount keeps the login collection locked.** With HOME (and so
  `~/.local/share/keyrings`) on a Docker Desktop bind mount, the login
  collection stays `Locked=true` however the password is delivered. On the
  container's own filesystem it unlocks. go-keyring then needs a prompt that a
  headless machine cannot answer: "failed to unlock correct collection".
- **On Linux, bind mounts enforce ownership.** gnome-keyring-daemon drops its
  capabilities after it starts, including `DAC_OVERRIDE`. As container root it
  then cannot create its control socket under a HOME that is a host-owned
  0700 bind mount. It exits quietly, and aw times out activating
  `org.freedesktop.secrets`. Docker Desktop ignores ownership on bind mounts,
  so this shows only on Linux.
- **Without `IPC_LOCK`** the daemon aborts with "error dropping process
  capabilities".

# How to apply

- Start dbus and gnome-keyring with `XDG_DATA_HOME`, `XDG_RUNTIME_DIR` and the
  bus socket on the container's own filesystem (for example under `/tmp`).
  Give the aw process the same `DBUS_SESSION_BUS_ADDRESS`.
- Feed the password only to `--unlock`. Other daemons get `</dev/null`.
- Add `cap_add: IPC_LOCK` to the service.
- Run lane machines as the host uid, with a mounted passwd entry, which dbus
  needs. Do not run them as root over host-owned mounts.
- Before blaming aw, check `Locked` with `dbus-send` on
  `/org/freedesktop/secrets/collection/login`.
- Reproduce lane failures on Linux, not only on Docker Desktop.

The elimination route is the lane's own container setup, which carries these
settings on the round-trip branch (`naapp/secrets/docker-compose.e2e.yml`,
`scripts/e2e-cross-registry-messaging.sh`). This lesson is for the next lane
or container that runs aw's human-key commands.

**Status (verified by the harvester 2026-11-12):** `IPC_LOCK` and
`XDG_RUNTIME_DIR` are set in those lane files on the branch
`agents/aweb-expert-owner-acts-roundtrip`, not on main at 88fbf7b4f.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-12;
notes/headless-keyring-in-containers.md and
notes/self-hosted-bundle-prerequisites.md. The macOS faults were observed in
lane bring-up on 2026-11-11 and the Linux faults on the dedicated VM on
2026-11-12, as the source reported.
