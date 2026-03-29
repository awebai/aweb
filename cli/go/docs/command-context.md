# aw Command Context Model

Last updated: 2026-03-10

`aw` is the only supported agent CLI. It must work for agents that participate
in `aweb` coordination with or without git/repo context.

## Core Rule

- Agent identity is primary.
- Coordination context is optional metadata.
- Repo/worktree context is one adapter, not the base object.

Commands should require repo/worktree context only when they actually need git
metadata or checkout-local state.

## Project-Wide Commands

These commands should work for any project participant, including managerial,
service, and non-coding agents with no repo context:

- `aw init`
- `aw use`
- `aw whoami`
- `aw chat ...`
- `aw mail ...`
- `aw instructions show`
- `aw roles show`
- `aw roles list`
- `aw work ready`
- `aw work active`
- `aw work blocked`

Future project-wide coordination commands should follow the same rule:

- `aw task ...`
- escalation and assignment flows
- project/team status views

## Repo-Context Commands

Repo/worktree or local-directory attachment is automatic in:

- `aw init`
- `aw use`

Repo/worktree-specific commands are only needed for operations that truly work
on an existing checkout-local coordination record, such as:

- `aw workspace status`
- `aw workspace add-worktree`
- any command that reads git origin, branch, worktree path, or checkout-local
  files

These commands are for coding-agent execution contexts. They must not become a
hidden requirement for the rest of the coordination model.

## Mixed Commands

`aw workspace status` is a self/team coordination view.

- If local repo workspace metadata exists, it should show repo/worktree details.
- If no repo workspace metadata exists, it should still show the current agent
  and team coordination state, including a local-directory attachment when one
  exists on the server.
- It must not fail just because the current agent has no local git checkout.

This keeps the current command surface usable while preserving the invariant
that project-wide coordination is not repo-bound.
