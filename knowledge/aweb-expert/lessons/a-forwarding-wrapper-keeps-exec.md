---
type: Lesson
title: A forwarding wrapper keeps exec
description: Replacing exec with a call plus an EXIT trap over function locals under bash set -u turns the child's exit status into 1 ("unbound variable"), and dropping exec also makes a caller's timeout kill only the wrapper, orphaning compose and leaking overlays; keep exec on every path and do setup before it.
tags: [lesson, bash, testing, gates, review]
timestamp: 2026-11-11
---

The gate's Docker wrapper (`candidate-gate/bin/docker`) ends every path with
`exec`, so the child's status is the wrapper's status and the child is the
process a caller signals. A branch (acwx, regression 9aafc64ec) replaced the
`exec` with a plain call and added `trap 'rm -f "$override" ...' EXIT` to
clean up temporary files. That broke two things.

- **Exit status.** Under `set -u` the EXIT trap fires at shell exit, after the
  function's locals are gone. It fails with "unbound variable", and its status
  (1) replaces the child's (2). A focused test and a code review both missed
  it; the first real gate run on a Linux VM caught it, reported as a
  federation failure with the wrong status.
- **Kill semantics.** Without `exec` the wrapper becomes compose's parent. A
  caller's `subprocess.run(timeout=...)` then SIGKILLs only the wrapper:
  compose is orphaned and keeps running past the caller's bound, and the
  override files leak.

A gate that reports the wrong failure code misroutes triage, and exit-status
changes are invisible to green-path tests.

# How to apply

- Keep `exec` on every path of a wrapper that forwards a command. Do the setup
  (overrides, temp files) before the `exec`.
- Where a parent genuinely must remain for a post-step, capture the status
  explicitly (`"$@"; status=$?; cleanup; return "$status"`), never rely on a
  trap over locals, forward signals and own a process group.
- A wrapper's tests assert pass-through of several non-zero codes (for
  example 0, 2 and 17) on every path, a failed `up` that must not attach the
  runner, and a timed call on both paths. This is the elimination route: the
  regression was shown red at 32cd15fb8 before the fix.
- Review a wrapper change that drops `exec` as a behaviour change, even when
  the diff looks like cleanup.

Related: [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
and [the first run on a new host type is a portability test](/aweb-expert/lessons/first-run-on-a-new-host-is-a-portability-test.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-11; notes/exit-trap-over-locals-masks-status.md and
notes/ephemeral-vm-gate-findings.md. The wrapper on main at 7f4be32fa was read
and ends every path with `exec`; the branch regression and its RED are the
source's report.
