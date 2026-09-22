---
type: Lesson
title: tmux isolation for agent runtimes
description: Use a per-team tmux socket and a guarded tmux first on the path for any harness that touches sessions; the aw team commands translate their own socket variable but raw tmux does not, and an inherited TMUX variable overrides the socket directory so the server holding the whole fleet can be invisible to every listing you run.
tags: [lesson, tmux, runtime, safety, aw-cli]
timestamp: 2026-07-27
---

Recorded by the OSS developer and coordinator roles in July 2026 after a
server-wide teardown had taken down every team's sessions at once, and after a
night in which every tmux listing the coordinator ran showed the same single
server because an inherited `TMUX` variable won over the socket directory.
Verified on 2026-09-21: `cli/go/cmd/aw/team_up.go` translates the aw socket
variable for its tmux children, and `scripts/guard-bin/tmux` is the reviewed
guard.

# The rules

- Never write or run ad-hoc tmux commands, scripts or inline cleanup traps
  against live sessions. A tmux-touching harness is committed, reviewed and run
  with the guard first on the path. Kill only a specifically named throwaway
  session; never the server.
- The aw team commands understand their own socket variable and translate it for
  their tmux children; raw tmux reads only its own variable or an explicit
  socket. Supplying the aw variable alone to raw tmux silently reaches the
  default socket.
- Use a per-team live-agent socket, never one socket shared across teams;
  launched process trees must inherit the guard path shim, which refuses
  server-wide teardown even when hidden in a script or subshell. Command-string
  hooks in a harness are secondary: they cannot inspect a command hidden in an
  invoked script.
- A session listing is not verification. An inherited `TMUX` value overrides the
  socket directory, so enumerate sockets and probe each explicitly before
  concluding how many servers exist.
- After a migration verify the old process exited by pid and working directory;
  a removed window is not proof, because a runtime that ignores hangup can
  survive as a detached orphan still connected to its channel.
