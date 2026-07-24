# Per-team agent tmux cutover

Live agents use separate socket directories so one team's failure cannot stop
another team or Juan's human/default tmux. The fixed convention is:

| Team | `aweb_tmux_tmpdir` | Authority |
|---|---|---|
| aweb/CLI | `~/.aweb/tmux/cli` | `aw-coordinator` |
| atext | `~/.aweb/tmux/atext` | atext coordinator/Juan |
| AC | `~/.aweb/tmux/ac` | `ac-coordinator` |

Only that team's authority executes its cutover. The migration harness is
`scripts/migrate-agent-tmux.sh`; do not translate these steps into ad-hoc tmux
commands or cleanup traps. The harness prepends the reviewed PATH guard, maps
the launcher variable correctly, and never performs server-wide teardown.

## Per-team procedure

1. **Preflight and dry-run.** From the reviewed aweb checkout, identify the team
   workspace and existing named session. Record the old socket from the old
   window's `TMUX` environment (`${TMUX%%,*}`), but do not retire it yet.

   ```bash
   scripts/migrate-agent-tmux.sh \
     --team TEAM --workspace WORKSPACE --session SESSION --phase launch
   ```

   Confirm the printed destination is exactly `~/.aweb/tmux/TEAM` (`cli` for
   the aweb team), the guard path is the repository guard, and the workspace
   binding is the intended `.aw/workspace.yaml`.

2. **Launch replacements.** This atomically persists `aweb_tmux_tmpdir`, creates
   its mode-0700 directory, and runs `aw team up --force --no-attach`. If the
   dedicated named session already exists, launch is skipped rather than
   creating duplicate windows.

   ```bash
   scripts/migrate-agent-tmux.sh \
     --team TEAM --workspace WORKSPACE --session SESSION --phase launch --apply
   ```

3. **Verify before cutover.** Run the explicit verify phase, then confirm every
   expected member has reconnected with `aw workspace status`, channel status,
   and a mail/chat round trip. Do not retire the old session on partial health.

   ```bash
   scripts/migrate-agent-tmux.sh \
     --team TEAM --workspace WORKSPACE --session SESSION --phase verify --apply
   ```

4. **Retire only the old named session.** Run this from Juan's outside/default
   terminal, not from a process inside the session being retired. It requires
   the exact old socket path and repeated session name, verifies the replacement
   first, and refuses self-termination. It invokes only `kill-session -t NAME`.

   ```bash
   scripts/migrate-agent-tmux.sh \
     --team TEAM --workspace WORKSPACE --session SESSION \
     --phase retire-old --old-socket /absolute/old/socket \
     --confirm-session SESSION --apply
   ```

For atext's currently stopped fleet, recover directly with step 2 on the atext
socket; there is no old session to retire. The aweb and AC authorities perform
their own full procedure independently.

## Rollback

Before old-session retirement, leave the old agents running and remove only the
new named session:

```bash
scripts/migrate-agent-tmux.sh \
  --team TEAM --workspace WORKSPACE --session SESSION \
  --phase rollback-new --confirm-session SESSION --apply
```

The dedicated workspace binding remains in place for a corrected relaunch. If
the old session has already been retired, do not recreate shared-default agents;
repair or relaunch the named session on the team's dedicated socket.
