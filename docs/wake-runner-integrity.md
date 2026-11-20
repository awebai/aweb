# Wake runner integrity

Only the bundle embedded in aw authorizes runner execution. The persistent
channel-core/runner.mjs cache is no longer read, created or rewritten. Remove
its old runner.sha256 success stamp before starting a child, so a downgraded aw
cannot trust stale bytes. A failed stamp removal warns with its path and recovery.

Existing wake state directories remain supported when shared or owned by another
UID. Warn once per affected state path with the exact chmod/chown command to make
it private; registration, inspection and startup remain available. Storage-managed
ancestor mounts and the unused legacy cache do not become eligibility gates.

Node executes a fresh private snapshot of the embedded bundle at 0700/0600 under
os.TempDir(), honoring TMPDIR. The parent must be owned by root or the effective
user, and must be sticky when writable by group or others. Refuse an unsafe actual
execution directory or temporary parent, with a repair and retry instruction.
Remove the snapshot after the child exits. On Unix, startup also removes this
user's own aw-wake-runner-* directories older than a day, excluding symlinks and
snapshots whose broker still holds their OS lock. Cleanup failures warn without
stopping wake delivery. Windows uses inherited ACLs and normal exit cleanup; stale cleanup
waits for an ACL ownership check rather than deleting an unproven owner's files.

A read-only root needs a writable temporary mount or a private writable TMPDIR.
Mode-fixture tests prove alternate temporary-directory selection; they do not
qualify a deployed mount or its options.

An invalid child status JSON line increments an invalid-output count without
retaining its contents or stopping valid neighboring status delivery.

The user-paths gate qualifies the released OATS kernel against candidate aw using
the real provider and an isolated passive tmux session. Its kernel wake receipt
is required; direct channel-core delivery alone does not qualify this seam. This
does not qualify a deployed image or Helm storage.

The probe creates its private deployment's `agents/` directory before calling
the released kernel. Its bootstrap control runs OATS 0.69.19 with an empty HOME,
no global Git identity and no parent checkout, so deployment discovery cannot
borrow the developer's environment. Failed kernel commands retain the JSON
error code while leaving private stdout out of diagnostics.
The control excludes Claude from PATH and checks that an unconfigured
`--no-launch` spawn refuses its unavailable harness before creating a home.
It then selects the installed Node executable through a local launch
configuration: the released kernel validates a future launch even when no
process is started. No placeholder harness executable is installed.

The wake journey selects a passive Codex launch backed by Node and an idle
script. Declaring it as Claude would make the released kernel call it with
`plugin list --json`; an idle executable cannot answer that discovery request.
The control exercises the released kernel's real launch planner with the
provider's conditional package requirement. Actual wake and terminal delivery
remain the user-paths stage's responsibility.

Command failures retain a child label, executable, PID, elapsed time, configured
deadline and bounded output tails. Credential-bearing aw calls withhold both
streams; lifecycle JSON diagnostics redact credential fields. The command
deadline remains 60 seconds. Diagnostics identify a failure without certifying
its underlying cause.
