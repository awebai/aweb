---
type: Decision
title: Only a final's own tag push moves an image's latest
description: An image lane's latest moves only when a final is published by its own tag push; an rc or a recovery dispatch publishes the immutable version only, because every way of deciding "is this the newest final" at publish time was rejected, and the workflow keeps one concurrency group per tag.
tags: [decision, release, images, ci]
timestamp: 2026-11-14
---

Decided on 2026-11-14 on the image publisher's latest-rule branch, after
release review refused two earlier designs. The rule itself is documented in
`docs/release.md` and implemented by `scripts/publish_release.py` and
`.github/workflows/service-image-release.yml` (merged to main in 4b75c076f).
This concept records why it is this narrow and what was rejected, so that
nobody widens it again.

# Decision

- On every image lane, `latest` moves only when a final is published by its
  own tag push.
- An rc publishes its immutable version tag only.
- A `workflow_dispatch` recovery (`--recovery`) republishes an existing tag's
  image, rc or final, and never moves `latest`. A recovery publishes something
  already released, so it never needs to.
- The workflow's concurrency group stays per tag. A dispatch joins the group
  of the tag it recovers.

# Rejected

- **Deciding "newest final" from the local tag inventory.** A stale clone
  answers wrongly. Release review reproduced this with real Git.
- **Deciding from the registry's mutable `:latest` config.** It cannot bind a
  version to a fixed multi-platform index: the tool reads one platform's
  config, chosen by platform, and the tag is not pinned to a digest.
- **One workflow-wide concurrency group to serialise latest moves.** GitHub
  keeps at most one pending run per concurrency group and cancels the pending
  run it replaces. A release that pushes three or more image tags at once
  would silently lose the middle publications.

# Accepted residue

Two finals of the same lane pushed close together can still finish out of
order, as before the rule. A direct publisher run without `--recovery` behaves
like a tag push and is not serialised against workflow runs. Both are
documented in `docs/release.md`. If either matters, fix it without the
rejected designs above.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14;
notes/rc-image-tags-and-latest.md. The harvester checked the rule and the
residue in `docs/release.md`, and the per-tag group with
`cancel-in-progress: false` in the workflow, on aweb main at 03f434b7c. The
review refusals (gate-vms 95316dac, 87fda234 and 10f800a8) and the source's
real rc publications, with latest unchanged, are source-reported. They are
agent records, not human acceptance.
