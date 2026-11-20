---
type: Lesson
title: Judge an image change by its platform manifest, not its index digest
description: A rebuilt team-deployment image gets a new OCI index digest even when its content is identical, and the Secrets and Logs images change their dependency layers on every commit; compare platform manifests, then diff the differing layers by path, type, mode and content and classify what differs before calling it a content change.
tags: [lesson, release, deployment, images, evidence]
timestamp: 2026-11-13
---

Observed on 2026-11-13 while comparing the team-deployment images built at
ad0fcc3d9 and at ba2edfad3. A changed image digest between two builds did not
mean changed content, for two independent reasons.

1. **The index digest is per build.** The builder pushes an OCI index that
   carries a BuildKit SLSA provenance attestation. The attestation records the
   build's start time, finish time and invocation id. So the index digest
   changes on every build, even when the platform manifest (config and layers)
   is byte-identical. cli-control rebuilt at an unchanged commit showed exactly
   this: the attestation differed only in those three fields.
2. **Secrets and Logs bake the commit in early.** `naapp/secrets/Dockerfile`
   and `naapp/logs/Dockerfile` set the `*_GIT_SHA` ENV and the
   `org.opencontainers.image.revision` LABEL from the `SOURCE_COMMIT` build
   argument right after `FROM`. Any new commit therefore invalidates every
   later layer, and `uv sync` runs again. In the comparison, the rerun changed
   only the uv cache under `root/.cache/uv`, the mtime field in the `.pyc`
   headers (all 1,860 `.pyc` files) and the dist-info `RECORD` and
   `uv_cache.json` files. No path outside those classes differed.

In the same comparison, five images had identical platform manifests. In the
cli image the only real change was `usr/local/bin/aw`, which matched a source
change between the two commits.

# How to apply

- To decide whether an image's content changed, compare the platform
  manifests, not the index digests. Identical platform manifests mean
  identical content, whatever the index digest says.
- When platform manifests differ, diff the differing layers by path, type,
  mode and content. Classify each difference as either a known noise class
  (the uv cache, `.pyc` header mtimes, dist-info `RECORD` and `uv_cache.json`)
  or a real change, and name the real changes.
- Do not settle a digest change by guessing either "provenance" or "cache".
  Each is a claim that the layer diff can confirm or refute. An unexplained
  digest change is not evidence of a content change, and it is not evidence
  of no change either.

The elimination route is a Dockerfile change, which belongs to the Secrets
and Logs owners: move the `SOURCE_COMMIT` ENV and LABEL after the dependency
layers, and keep the uv cache out of the image. Then those images stay
identical across commits that do not touch their inputs. Until that change
lands, the comparison above is the check.

This applies
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
to images: a claim about an image is about its content, and a digest that
also encodes build metadata does not identify that content.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/image-digest-changes-without-content-changes.md. The harvester checked
on aweb main that both Dockerfiles set the ENV and LABEL from `SOURCE_COMMIT`
before the dependency layers. The registry comparison and its counts are
source-reported.
