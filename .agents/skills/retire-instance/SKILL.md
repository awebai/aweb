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

Run from your own agent home:

```bash
name=<name>
REPO="$(cd "$(git rev-parse --git-common-dir)" && cd .. && pwd)"
inst="$REPO/agents/instances/$name"

aw team remove-agent "<namespace>/$name"          # claims, workspace, certificate
aw team agent-status "$name"                      # read it back before deleting anything

git -C "$REPO" worktree remove "$inst/worktree" --force 2>/dev/null
rm -rf "$inst"
git -C "$REPO" branch -D "$name" 2>/dev/null
git -C "$REPO" worktree prune
```

`aw team remove-agent` covers the network state: it deletes the workspace
record — which is what releases the task claims held under it — and then
revokes the certificate, in that order. Do not revoke first. An agent can
release its own claims right up until its certificate is revoked, and the
hosted removal deletes the same workspace record without releasing
anything, so a revoke that runs first strands every claim it held.

## Read it back before you delete the home

`aw team agent-status <name>` reads the stores directly and mutates
nothing. It is the check that the retirement actually happened, and it is
deliberately not the retire command reporting on itself. A retired agent
reads `state: clear` — no active certificate, no workspace, zero claims,
and `name free: true`.

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
  registry. Run `aw team agent-status` to establish the real state; it reads
  the registry.

On a customer-controlled team, retiring a name that no longer resolves is
an error rather than a no-op, so re-running a completed retirement by name
fails there. That is deliberate: a lookup that finds nothing looks exactly
like a request that never reached the registry, and reporting that as a
successful removal is how a bulk retirement can report success for targets
it never touched.

Use `aw team remove-agent`, **not** `aw id team leave` — leave refuses an
identity's only team. If the instance died before cleanup and the member is
orphaned in the roster, remove it via the dashboard.
