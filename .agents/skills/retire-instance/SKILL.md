---
name: retire-instance
description: Remove a teammate — retire an instance's aweb identity and workspace, then its home, worktree, and branch. Use when an instance's job is done (a developer whose branch merged, a reviewer that gave its verdict).
---

# Retire an instance

One-shot instances are retired when their job is done, so teammates don't
pile up on the network. Standing instances (the coordinator) are
long-running and not retired this way.

**Preserve first.** Before removing anything, make sure useful branch work
is merged or pushed, and anything the instance learned that belongs in its
soul is committed (see `self-maintenance`).

## The verb depends on the agent's identity scope

These are different lifecycle stories and `aweb-sot.md` says they must not be
conflated. Establish the scope before choosing a command.

Read your own with `aw workspace status`; the spawn spec that created the agent
carries it too: `[NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]`.

- **Local identity scope** — spawned `:local`, a name on one team, no `did:aw`,
  no registry certificate. This is the common case: a coordinator's own workers
  are local. The verb is **`aw workspace delete`**, which the SOT calls "the
  single user-facing lifecycle verb for local teardown".
- **Global identity scope** — holds a `did:aw` and a registry certificate. The
  verb is `aw team remove-agent`, the identity/certificate revocation primitive.
  Hosted removal needs a team-scoped owner/admin API key; a workspace-bound key
  is rejected, so this is not something an agent workspace can do alone.

Using `remove-agent` on a local agent produces an accurate refusal about missing
owner/admin credentials. That error is about the wrong verb, not about a missing
permission — it is easy to read as a capability boundary and it is not one.

## Stop the runtime before you run anything below

**This is a manual prerequisite and it is not in the command block, because it
cannot be.** Deleting the workspace does not stop the process: it leaves a live
agent running against an identity that no longer exists. That has already
happened — four `pi` runtimes kept running after their workspaces were deleted,
and nothing warned.

**Who does it:** whoever holds the keyboard or the tmux session — in practice the
human running the fleet. Not the retiring agent: it cannot quit itself, because
every command it runs is a child of the runtime you are trying to stop, and a
process cannot exit its own parent by returning from a child. Not a sibling agent
either: killing another agent's process is fenced by this project's tmux rules.
So ask the human, and confirm the process is gone before continuing.

    In Claude Code: `/quit` in that agent's own window, or close the window/pane.
    For pi: quit or close that interactive process.

Confirm it stopped — the old pid gone AND no runtime left in that home — rather
than assuming the request was acted on.

Then run the rest from your own agent home:

```bash
name=<name>
REPO="$(cd "$(git rev-parse --git-common-dir)" && cd .. && pwd)"
inst="$REPO/agents/instances/$name"

# LOCAL identity scope (the usual case):
aw workspace delete "$name"                       # workspace + local identity

# GLOBAL identity scope only — needs an owner/admin key:
# aw team remove-agent "<namespace>/$name"        # claims, workspace, certificate

git -C "$REPO" worktree remove "$inst/worktree" --force 2>/dev/null
rm -rf "$inst"
git -C "$REPO" branch -D "$name" 2>/dev/null
git -C "$REPO" worktree prune
```

**`aw team remove-agent`'s exit status is reliable — branch on it.** It returns
non-zero when a store did not reach a terminal state (`cliError{code: 1}`), and
the owner/admin refusal is a usage error (code 2). Its own help calls the status
values a contract.

**What is not reliable is an `aw` subcommand you have not confirmed exists.** An
unknown subcommand prints the parent help and exits 0, so a script sees 1.6 KB of
usage text as success. That is a property of unrecognised verbs, not of
`remove-agent`.

`aw team remove-agent` covers the network state: it deletes the workspace
record — which is what releases the task claims held under it — and then
revokes the certificate, in that order. Do not revoke first. An agent can
release its own claims right up until its certificate is revoked, and the
hosted removal deletes the same workspace record without releasing
anything, so a revoke that runs first strands every claim it held.

## Read it back before you delete the home

Confirm the retirement from something other than the retire command reporting on
itself. That independence is the whole point of this step:

> `team_agent_status.go:68` — "It exists so that the evidence an agent is retired
> comes from somewhere other than the command that retired it."

```bash
aw team agent-status "$name"        # preferred: reads the stores directly
```

**Availability, and check this before relying on it.** `aw team agent-status` is
registered on `main` (`team_human.go:264`, added in `52995ab6`) but that commit is
**not in `aw-v1.34.1`**, so on an installation at that release the verb does not
run: it prints the parent help and **exits 0**, and a script reads 1.6 KB of usage
text as a successful status check. Confirm it exists on your installation before
trusting its result — and note this is how *any* unrecognised `aw` subcommand
behaves, not a property of this one.

**How to check, because the obvious way silently says yes.** `aw team
agent-status --help` exits 0 on an installation without the verb — it prints the
parent help. The check that discriminates is the listing:

```bash
aw team --help | grep -w agent-status     # no output -> the verb is not there
```

**If it is unavailable, say which check you used.** The fallback is to read what
`aw workspace delete` reported plus the team's workspace listing. That is weaker
and you should know why: the first half is the retire command reporting on itself,
which is exactly the dependence `agent-status` exists to remove. Substituting it
is acceptable; presenting it as equivalent is not.

`clear` describes what the stores hold now, not how they came to hold it. A
name retired this morning and a name never used read the same way, because
this command cannot establish which it is looking at and will not guess.

**Never delete the home while the server still considers the member
active** — that orphans it in the roster. The status read is how you know.

## What the outcomes mean

`remove-agent` reports each store separately, because they fail
independently.

- **`incomplete`** — a store did not reach the state retirement wants, and
  the output says which. The command exits non-zero. The common case is
  `local_workspace_still_active`: a workspace seen within the last 30
  minutes cannot be deleted, so its claims cannot be released. Wait for
  presence to go stale and run it again. The command stops before revoking
  in that case rather than leaving an agent with no credential and claims
  nobody can clear. If you need access revoked immediately and accept that
  outcome, use `aw id team remove-member`.
- **`retired`** — every store reached that state and each one established
  it.
- **`reported_retired`** — every store reached that state, but the
  certificate part rests on the hosted service reporting it had nothing to
  revoke. That is not the same as knowing no certificate exists: the hosted
  service answers from its own membership records and may never consult the
  registry. Establishing the real state needs a read against the registry
  itself: `aw team agent-status` where it is available (see above), or
  `aw id team` inspection where it is not.

On a customer-controlled team, retiring a name that no longer resolves is
an error rather than a no-op, so re-running a completed retirement by name
fails there. That is deliberate: a lookup that finds nothing looks exactly
like a request that never reached the registry, and reporting that as a
successful removal is how a bulk retirement can report success for targets
it never touched.

Use `aw team remove-agent`, **not** `aw id team leave` — leave refuses an
identity's only team. If the instance died before cleanup and the member is
orphaned in the roster, remove it via the dashboard.
