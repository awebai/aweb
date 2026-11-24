---
type: Decision
title: A release manifest by digest is a deployment's only image input
description: The team deployment repository takes every image from one release manifest pinned by digest, with no image keys in deployment.yaml, admits unpublished images only as lab-flagged candidates built from an exact commit, and consumes each runtime's deploy files from inside its pinned image; a second pin anywhere was rejected because two pins drift.
tags: [decision, deployment, release, images, digest, oats]
timestamp: 2026-11-24
---

Decided on 2026-11-24 while the team deployment (aweb, its apps and its
agents) moved out of the aweb repository into its own deployment repository,
so that the deploy path stops depending on aweb's source and release trains.
It is the consuming side of the release rule that every service the team
bundle runs ships a published, digest-pinned image (a decision under review
when this was written).

# Decision

**One manifest is the only image input.**

- Every image a deployment runs, third-party ones such as postgres and redis
  included, comes from one release manifest (`release.json`). Each entry is
  pinned by digest and records its platform, its status (`published` or
  `candidate`) and its source.
- `deployment.yaml` names no image. A `deployment.yaml` that still carries
  image keys is refused by name, with a test, rather than silently ignored.
- The entries required follow the services selected. A missing digest or a
  platform mismatch refuses before anything is rendered.
- The deployment records the release's sha256 with its run and its backups. A
  changed release is an explicit upgrade from a backup, never a silent
  restart.

**Candidates are a lab path, not a second code path.**

- An image that has not been published enters only as a `candidate` entry,
  built from an exact source commit, and goes through the same pull-by-digest
  path as a published one. Evidence therefore still binds to bytes.
- A candidate runs only under an explicit lab flag. A team's (customer)
  deployment applies `published` entries only.
- When the repository holds a service's run contract as a file (a compose
  fragment, say), that service must run an image from the same commit of the
  same producer. Third-party images and independently authored wrappers record
  their own provenance and the pinned pairing instead.

**A runtime's deploy contract comes from its own image.**

- The OATS agent and egress images carry their compose fragments and host
  scripts under `/opt/oats/deploy`, with a `manifest.json` listing the source
  commit, the installed versions and a sha256 for each file. The egress tree
  keeps its source hierarchy, so it is extracted whole with its import
  closure.
- The deployment copies these files out of the pinned digest. It refuses any
  file the manifest does not list, any source commit other than the
  release's, and any shared file that differs between the two images.
- The image digest is the only pin for those files.

# Rejected

- **Image pins in both `deployment.yaml` and the manifest.** Two places can
  disagree, and the operator cannot tell which one ran.
- **Building any component from source in the deploy path.** It ties
  deployment to the producers' source trees, which is what the split removes.
- **A separately versioned deploy artifact** (an npm package or tarball)
  pinned beside the image digests. That is two pins that drift, the same skew
  OATS #1913 removes for its kernel.
- **Vendored copies of runtime files** in the deployment repository. They are
  a second, hand-maintained pin of the same contract.

# Status

On 2026-11-24 the manifest and the image-borne deploy files existed on a
review branch of the deployment repository. Nothing in that range had run on
Docker yet; the gate-VM rehearsal was pending. Rollback is a restore of the
pre-upgrade backup where the component supports restore; restore was proven
only in lab rehearsal.

# Acceptance

- Manifest, candidate rule and removing the image keys: ruled by the
  deployment coordinator on 2026-11-24 (mails fd860c04 and 9c9b48ef), and
  agreed with the owner of the team-deployment task (mail 3b44be7e).
  Source-reported.
- Deploy files carried in the images: agreed with the OATS contact on
  2026-11-24 (mail 4fbc2172), source-reported. Shipped as OATS PR #2117,
  merged at 0e386f0f6; the harvester verified the merge on GitHub.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-repo, 2026-11-24;
notes/manifest-is-the-only-input.md, notes/manifest-rules-from-acwd25.md,
notes/oats-images-carry-their-deploy-files.md. The deployment repository
commits it cites (e4fff0c, 69cfdc4) are source-reported.
