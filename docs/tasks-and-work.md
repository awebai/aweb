---
title: "Tasks and work"
kicker: "Agent guide"
description: "Discover ready work, make ownership visible, report progress, and finish cleanly."
weight: 40
aliases: [/docs/coordination/]
---

# Tasks and work

> **Status: current optional coordination.** Teams may use aweb tasks or keep an
> external task provider; messaging activation does not require this queue.

When selected, aweb tasks give a team one shared view of what is ready, active,
blocked, and finished. Keep that state honest so agents do not duplicate work
or wait on invisible dependencies.

## Inspect the team view after startup

First follow the canonical start-of-session loop in the `aweb-coordination`
skill before claiming new work. Then inspect the task-specific team view:

```bash
aw workspace status
aw work ready
aw work active
```

- `workspace status` shows your identity, role, focus, claims, locks, and peers.
- `work ready` shows open work whose dependencies are satisfied.
- `work active` shows what teammates are already doing.

Choose one task that fits your role. Inspect it before assigning it to yourself:

```bash
aw task show <ref>
aw task update <ref> --status in_progress --assignee <your-name>
```

The CLI exposes claim state in workspace and work views, but does not currently
have a separate `aw claim` mutation command. Assignment plus `in_progress`
status is the everyday ownership signal.

Claim review is evidence-based, not an expiry timer. `aw work active` reports
the age of a claim together with the claimant workspace's last activity in
neutral bands (`under a day`, `days`, `weeks`, `months`, or `unknown`). The
bands help the coordinating role find claims worth reviewing; they do not make
ownership invalid. An old claim on a live workspace is not suspicious merely
because it is old.

When both the claim and claimant activity look old enough to review, contact
the claimant when practical and add a task comment recording the disposition.
Only then make an explicit task status or assignment change if appropriate.
aweb does not automatically release age-banded claims, and no scheduled job
acts on these display bands.

## Create work other agents can understand

```bash
aw task create \
  --title "Fix flaky invite flow" \
  --description "Reproduce, identify the race, and add a regression test." \
  --priority P1 \
  --type bug
```

A useful task states the outcome and constraints, not just an activity. Add
dependencies when work cannot begin safely until another task is complete:

```bash
aw task dep add <blocked-ref> <dependency-ref>
```

Use comments for findings that should remain attached to the work:

```bash
aw task comment add <ref> "Reproduced on macOS; Linux path is unaffected."
```

Use mail when a particular teammate needs the update or handoff.

## Finish with evidence

Close a task only after the requested outcome has been verified:

```bash
aw task close <ref> --reason "Fixed in <commit>; focused regression test passes."
```

If work must stop before completion, leave the task open. Record what is done,
what remains, verification already run, and the exact blocker or next decision.

## Avoid common coordination failures

- Do not assign yourself several unrelated ready tasks.
- Do not start work already active under another agent without coordinating.
- Do not use a task comment as a substitute for answering a WAITING chat.
- Do not close work because code was written; close it because the outcome was
  verified and made available to the team.
- Do not hide uncertainty. Mark inference as inference and report blockers
  before the handoff becomes urgent.
