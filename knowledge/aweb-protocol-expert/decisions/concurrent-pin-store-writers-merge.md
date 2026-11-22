---
type: Decision
title: Concurrent pin-store writers on one home merge
description: The trust pin store is shared by every aw process of a machine user, so its compare-and-set three-way merges a commit another writer made with this writer's change and refuses only a same-key conflict (one address pinned to two keys, or a checkpoint fork); last_seen keeps the later time and a doubly advanced checkpoint keeps the higher sequence. Retrying in each command and threading one snapshot through a command's writes were rejected. Decided; on a review branch, not yet on main.
tags: [decision, aw-cli, trust, pins, concurrency, oats, headless]
timestamp: 2026-11-21
---

The peer continuity pins (`known_agents.yaml`) belong to the machine user's
HOME, not to the identity home
([identity selection is one precedence rule](/aweb-protocol-expert/decisions/identity-selection-is-one-precedence-rule.md)).
Every agent on an OATS host therefore writes the same store, and so does every
actor of a test lane that runs all its actors under one HOME.

The pin-store compare-and-set refused any write whose precondition snapshot
was stale. On 2026-11-21, in the user-paths waiting-chat lane, one agent's
`aw chat send-and-wait` was waiting while a second agent, in another process,
pinned the first and recorded its checkpoint. The waiting agent's reply
verification then lost its own pin and checkpoint saves, and a verified reply
was reported `verification_stale`. Released aw wrote without a
compare-and-set, so it had passed. The conflicting writer was another
process; within one client a successful save already advances the baseline.

# Decision

Fix it at the pin-store owner, for every caller. Under the lock, a stale
precondition three-way merges base (what this writer read), ours (what it
wants to write) and current (what is on disk):

- A key only one side changed takes that side.
- A pin both sides changed merges field by field; `last_seen` keeps the later
  time.
- A checkpoint both sides advanced keeps the higher sequence, or the later
  fetch time of the same entry.
- **Refuse only a real conflict**: both sides set the same key to different
  values (one address pinned to two keys), or a checkpoint fork (the same
  sequence with a different entry hash). The refusal keeps the "trust pin store
  changed since it was read" wording, so callers that classify that conflict
  still match.
- The merged store must reparse; a dangling address counts as a conflict.

A refusal is correct when two writers really disagree about a key. Anything
else is friction for headless agents sharing one OATS home, which the
operator's no-added-friction rule for headless users forbids.

# Rejected

- **Retrying in the command that failed** (chat). It fixes one caller and
  leaves send-and-leave, mail and channel-core exposed to the same stale
  precondition.
- **Threading one snapshot through a command's writes.** It fixes only a
  self-conflict, and this conflict came from another process.

# A refusal test must reach the guarded step

The test that should have guarded the compare-and-set
(`TestConfigureResolvedClientUsesCASForGoTrustWrites`) expected "stale" for
a first contact that never reached the compare-and-set: it had no resolver,
so the client stopped before any write. It passed and guarded nothing. A test
that asserts a refused or downgraded outcome must also show that the code path
reached the guarded step, for example by a control in which the same setup
without the conflict does write. The rewritten test keeps a merge case and a
control in which the same address pinned to another key is still refused.

Status: implemented on branch `agents/aweb-protocol-expert-chat-verify-pincas`
(fix b57345ac8e, tests b6b7b7e179; merge in `awid.MergePinStoreChanges`),
verified there by the harvester. Not yet on main or released.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/pin-store-writers-on-one-home-merge.md, notes/headless-users-get-no-added-friction.md. The gate run and the reviewer's guidance relayed by the coordinator are source-reported.
