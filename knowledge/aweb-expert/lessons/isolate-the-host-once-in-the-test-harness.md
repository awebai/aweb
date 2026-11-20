---
type: Lesson
title: Isolate the host once, in the test harness
description: When a test package fails on a developer's or agent's macOS host but passes in the gate, fix it in the package's TestMain (canonical TMPDIR, production's own agent-marker list unset, a pinned Python checked against the gate image), never with skips, gate-only environment or a weaker production check; canonicalising macOS's per-user TMPDIR then pushes socket paths past the 104-byte limit.
tags: [lesson, testing, harness, macos, gate]
timestamp: 2026-11-13
---

Agents run the aw test suites on macOS, with their runtime variables set. The
gate runs them on a Linux image without either. A package that is green in the
gate can therefore be red on every agent's host. On 2026-11-13, `go test` for
`cmd/aw` and `internal/custodypath` on a macOS host gave 54 failures from three
causes, and each cause has a tempting wrong fix.

# The rule

The package's TestMain absorbs host differences once, before anything is
created or captured for child processes. Dev hosts and the gate then run one
test path.

1. **Symlinked temporary directories.** On macOS, /tmp and /var are symlinks.
   aw refuses identity homes, locks and custody paths under a symlinked parent,
   and that refusal is a custody property that stays. The harness sets TMPDIR
   to the resolved temporary directory.
2. **Agent runtime variables.** CLAUDECODE, CLAUDE_CODE_ENTRYPOINT,
   CODEX_THREAD_ID, OATS_INSTANCE and OATS_INSTANCE_HOME come from whoever runs
   the tests. The harness unsets every name in production's own
   `agentRuntimeMarkers` list, not a copy of it, so a marker added to the
   production guard is scrubbed automatically. A test that needs a marker sets
   it itself.
3. **Floating toolchains.** `uv run --project X` without a pin uses the host's
   newest Python, and the locked native dependencies may not build for it. The
   project pins its Python with `.python-version` at the gate image's version,
   which every `uv run` in that project honours. A guard test compares the pin
   with the gate Dockerfile's `FROM` line.

Each property has a guard test. The guards were shown to fail before the
harness change and to pass after it
([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

# Rejected

- **Skipping on darwin or on CLAUDECODE.** The cause stays hidden, and the
  tests stop running where agents run them.
- **Setting the variables only in the gate.** That makes a second test path,
  and a dev host then has gate-only surprises.
- **Passing `--python` in one fixture.** Other `uv run` calls in the same
  project would still float to the newest Python.
- **Letting production accept symlinked parents.** The refusal protects
  custody, and a test inconvenience is no reason to weaken it.

# Trap

Canonicalising macOS's per-user TMPDIR (under /private/var/folders) makes test
socket paths longer than the 104-byte Unix socket limit. This only appeared
when the tests ran with that TMPDIR, after the first green run. The wake tests
hit the same limit independently. Socket tests use a short canonical directory
created under the resolved /tmp.

# Status

As of 2026-11-13 the harness change (`cmd/aw` TestMain, the
`internal/custodypath` socket fix and `awid/.python-version`) is on a branch
under review and not yet on main. The source had not run the gate with it. On
the gate's Linux image the changes are no-ops by construction. Any new test
package or fixture that builds its own harness meets the same three causes.

Evidence: OKF proposal from aweb-expert/aweb-expert-wake-fixes, 2026-11-13 (tasks aweb-aczf and aweb-acyy); notes/one-test-path-on-dev-hosts-and-gate.md.
