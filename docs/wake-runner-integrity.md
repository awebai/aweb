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
