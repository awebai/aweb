---
type: Lesson
title: Build on a peer's unlanded branch in a separate tree
description: Work that depends on a peer's unlanded branch goes in an extra tree based on that branch, never merged into your own landing branch, because their branch can be held back and then yours cannot land on its own.
tags: [lesson, git, coordination, landing]
timestamp: 2026-11-13
---

A display branch merged a peer's unlanded commit so that the page could render
a field the peer's change added. The coordinator then ruled that the peer's
change must not land before a separate correction. The display branch could no
longer land on its own: it had to be rebuilt from main without the merge. Its
commits were still unpushed, so no public history was rewritten, but the
rebuild was lost work.

The later change that needed the peer's route was built in a separate tree
based on the peer's branch, and landed independently of the display work.

How to apply: keep your landing branch as main plus your own reviewed commits.
When a change needs a peer's unlanded work, build it in an extra tree based on
their branch (`oats worktree add --purpose <p> --branch <b> --base <their remote branch>`), and tell the peer
and the coordinator which head composes the two.

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/compose-unlanded-peer-work-in-a-separate-tree.md. The harvester checked
that 1191212203 is not on main and that the dependent change (5e65ae708) sits
on its own owner-removal branch.
