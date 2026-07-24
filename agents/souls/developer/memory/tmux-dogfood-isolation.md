# Tmux dogfood isolation

Never write or execute ad-hoc tmux dogfood commands, scripts, or inline cleanup traps. A tmux-touching harness must be committed, reviewed, and run with `scripts/guard-bin` first on `PATH`. Kill only a specifically named throwaway session; never use `tmux kill-server`.

The variable boundary is a critical trap:

- `aw team up` / `aw team add --start` understand `AWEB_TMUX_TMPDIR` and translate it for their tmux children.
- Raw `tmux` does **not** understand `AWEB_TMUX_TMPDIR`; it reads `TMUX_TMPDIR` (or an explicit socket). Supplying only the aweb variable to raw tmux silently reaches the default socket.

Use a per-team live-agent socket (`~/.aweb/tmux/<team>`), not one socket shared across teams. Launched agent process trees must inherit the generated tmux PATH shim, which refuses server-wide teardown even when it is hidden inside a script, trap, or subshell. Claude/Pi command-string hooks are secondary: they can block visible destructive commands but cannot inspect commands hidden in an invoked script. The PATH shim and per-team socket are the runtime-agnostic layers.

For migration or recovery, use the reviewed repository harness and runbook. Verify the replacement session and channel connectivity before retiring only the old named session. Never infer safety from an empty isolation variable, and never touch another team's socket.
