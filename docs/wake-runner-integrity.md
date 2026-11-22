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

The wake journey explicitly configures a passive Node program as its terminal
executable, with Codex session delivery. The program has a shebang naming the
installed Node interpreter; kernel-inserted Codex arguments become script argv.
Naming Node itself as the executable would make those arguments interpreter
options (`-c` requests a syntax check) and terminate the terminal instead.
No executable named `codex` or `claude` is installed or impersonated, and this
fixture does not certify model execution. The control starts the real released
kernel session, checks independent terminal liveness after one idle second,
and retires the home. Actual provider, wake and mail delivery remain the
user-paths stage's responsibility.

Every probe assertion records its named inputs before verification, using one
receipt owner. Booleans, numbers, public state words, UTC timestamps and file
modes are retained; opaque strings and objects are withheld. The full public
wake snapshot is saved before the quiet-start and idle assertions, so a failed
check retains its actual `last_input_at`. Assertion failures keep their cause
and identify the check and receipt without printing private compared values.

`ChannelCoreStatus.LastInputAt` is a Go `time.Time`: no broker input can appear
as the nonempty JSON string `0001-01-01T00:00:00Z`. The probe accepts that zero,
an omitted field or the child's empty string as absence. It still refuses
nonzero or malformed values before the controlled mail. The runner updates
this timestamp only after a submitted `session input`; the startup observer
only calls `session inspect` (terminal-wake-broker.md:195-200). The released
kernel's TASK prompt is launch argv, not this broker input receipt. Generation
zero is omitted by Go JSON too; the probe compares its numeric default and the
runner's actual start time to retain the same-generation/process check.

Released plain `retire --json` returns a direct receipt, not an `ok` envelope:
cleanup requires the exact instance, home removal and confirmed provider
retirement/alias release.

Command failures retain a child label, executable, PID, elapsed time, configured
deadline and bounded output tails from known non-secret producers. All kernel
lifecycle and aw status/credential calls withhold both streams, retaining only
the safe error code and child identity/timing/status/cause fields. The command
deadline remains 60 seconds. Diagnostics identify a failure without certifying
its underlying cause.
