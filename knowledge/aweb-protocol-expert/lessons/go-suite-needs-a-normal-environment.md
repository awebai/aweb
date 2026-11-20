---
type: Lesson
title: The aw Go suite needs a normal environment
description: In an agent sandbox, go test ./... in cli/go fails spuriously because a symlinked /tmp is refused by the custody paths, the agent-runtime markers trip the human-participation guards, and a long TMPDIR breaks unix socket paths and hangs the wake package; rerun with a short real TMPDIR and CLAUDECODE and CLAUDE_CODE_ENTRYPOINT unset before attributing a failure.
tags: [lesson, testing, go, cli, environment, agent-runtime]
timestamp: 2026-11-09
---

On 2026-11-09, in a Claude Code session on macOS, `go test ./...` in `cli/go`
reported more than 30 failures unrelated to the change under test. The whole
suite then passed under a corrected environment. There were three causes, each
a guard working as designed:

- **A symlinked `/tmp`.** On macOS `/tmp` is a symlink, and the custody and
  recovery-lock paths refuse a symlinked parent.
- **Agent-runtime markers.** `CLAUDECODE` and `CLAUDE_CODE_ENTRYPOINT` are set
  inside the session. The human-participation guards treat them as agent
  runtime markers (`agentRuntimeMarkers` in `cli/go/cmd/aw/id_human.go`) and
  refuse.
- **A long `TMPDIR`.** Unix socket paths built under it pass macOS's 104-byte
  limit (`bind: invalid argument`). That also hangs the wake package until the
  10-minute test timeout. Under the corrected environment, wake alone took
  about 240 s.

A pty test can also fail once with "device not configured" and pass on rerun.

# How to apply

Before calling a Go failure pre-existing, or your own, rerun it like this:

```sh
env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT TMPDIR=<short real directory> go test ./...
```

A failure that disappears there is the environment. Report it as that, not as
a bug, and do not block a landing on it.

# Real fix

This is knowledge debt. Tests that need the human path could clear the markers
themselves with `t.Setenv`, and socket and custody tests could make their own
short, non-symlinked directories. The suite would then pass in any
environment. Until that is done, this lesson is the workaround.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/go-suite-needs-normal-env.md.
