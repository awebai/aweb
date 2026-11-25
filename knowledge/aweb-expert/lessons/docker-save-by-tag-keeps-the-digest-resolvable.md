---
type: Lesson
title: Docker save by tag keeps the digest resolvable
description: With the containerd image store, docker save by digest writes no ref name, so after docker load the image has no tags or digests and no longer resolves by its digest reference; tag it locally and save by that tag to keep repo@digest resolvable.
tags: [lesson, docker, containerd, images, gate]
timestamp: 2026-11-25
---

Shipping a tested image to a machine with no registry access, where a check
addresses the image as `repo@sha256:<digest>`, needs the loaded image to keep
its name.

With the containerd image store, `docker save repo@sha256:<member>` writes an
archive whose index carries no ref-name annotation. After `docker load` the
image has no RepoTags and no RepoDigests, and `docker image inspect
repo@sha256:<member>` answers "No such image"; only the bare image ID
resolves. Saving the multi-platform index by digest with `--platform` behaves
the same.

Tagging the platform member locally as `repo:<tag>` and saving by that tag
keeps the name: after load, `repo@sha256:<member>` resolves, its Id is the
member digest and RepoDigests is `[repo@sha256:<member>]`.

# How to apply

- Save by a local tag, never by digest, when the receiving side resolves the
  image by digest. The tag can be local only: remove it after saving and never
  push it.
- After load, check that the digest reference resolves before the run relies
  on it.

Observed on Docker 29.8.1 only; not verified on 29.9.3 or later. Recheck on
the receiving engine's version.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/docker-save-by-digest-loses-the-name.md. Tested once with a public base
image's amd64 member, then cleaned up.
