---
name: aweb-tasks
description: Use only when the team has aweb tasks or its instructions say it uses them, for sharing tasks, claiming work, and the ready/active loop. Otherwise use the team's own tracker. Creating the first task is the opt-in.
allowed-tools: "Bash(aw *)"
---

Use this skill only when the team has aweb tasks or its instructions say it uses them. Otherwise use the team's own tracker. Creating the first task is the opt-in; do that when the user or team deliberately chooses aweb tasks, never merely because aweb messaging or these skills are installed.

# aweb Tasks

## Choosing the team's tracker

Read `aw instructions show` and the team's existing work context. If the tracker
is unclear, `aw task list` is a read-only way to check whether the team has tasks.
Empty `aw work ready` and `aw work active` results do not establish that the team
has no tasks: it may have only closed tasks. An unavailable task service is an
error, not evidence of an empty team. Do not create a task just to discover
whether this skill applies.

## Ready and active loop

First complete the session loop in `aweb-coordination`: team status, waiting
mail, then pending chat. If that skill is unavailable, run `aw workspace status`,
`aw mail inbox`, and `aw chat pending` in that order before discovering work.
Then inspect the current team's work:

```bash
aw work ready          # smallest actionable unclaimed item
aw work active         # check who already owns related scope before claiming
aw work blocked        # dependencies or external answers
aw task show <task-id>  # read comments and dependencies before acting
```

Tasks record work and ownership where teammates can see it. Follow the team's
assignment policy and keep status and comments current instead of maintaining a
private duplicate tracker. This choice is per team; another team may use a
different tracker.

## Sharing tasks

A task is the durable record of a unit of work. Anyone in the team can see it; it doesn't depend on local notes.

```bash
aw task create --title "<title>" --description "<details>"
aw task list                         # filter with --status, --assignee, --labels
aw task show <task-id>
aw task update <task-id> --status in_progress
aw task comment add <task-id> "validation results, blockers, decisions"
aw task close <task-id> --reason "what landed and where validated"
aw task dep add <task-id> <depends-on-id>     # express dependencies
```

When creating a task: keep the scope small enough that one agent can complete it. Put what's known into the body so a teammate can pick it up without asking. If something only one agent knows is needed to finish, name them in the body.

## Requesting a human decision

A task assigned to a human is a request. Humans are valid task assignees in
the same team even though the agent roster does not list them. Assign the
request to the human whose message you are acting on, using that message's
alias. Do not guess from a display name or try to discover humans through
the roster. State the question, relevant options and what it unblocks, and
keep the task open while waiting. Do not mail the human first: agents cannot
start a conversation with a human. After creating the request, end your turn:
do not poll or sleep waiting for the answer.

The answer usually arrives as mail from that human (the hosted dashboard
sends it as `Re: <ref> <title>`). It may instead be a task comment, or the task
may be closed. When you are woken, check `aw task show <ref>` (MCP: `task_get`
and `task_comment_list`), read the answer and update the task accordingly.

## Claiming work

To take a ready task, mark it in-progress (this is the claim — the team sees you own it):

```bash
aw task update <task-id> --status in_progress
```

Before claiming, run `aw work active` to make sure nobody is already on the same scope. Keep the claim small: claim the smallest actionable task, not the broad epic. Coordinators may move work around without claiming every subtask.

When status changes, update the task. Valid status values are `open`, `in_progress`, and `closed` (use `aw task close <id>` to close). Closing with `--reason "..."` records why; comments capture validation evidence and decisions.

If you stop work on a claimed task without finishing — handoff, abandon, or block — move it back out of `in_progress` so the team sees it's available again: `aw task update <id> --status open` and leave a comment naming what was done so far and what's left. Mail the teammate who can unblock or continue.

## Wrap-up

Update task status and close finished tasks with
`aw task close <id> --reason "what landed and where validated"`. If work remains, record the handoff or
blocker and release the claim as described above. Follow `aweb-coordination`
for mail handoffs, locks, and waiting chats.
