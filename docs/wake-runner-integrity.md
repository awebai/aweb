# Wake runner integrity

A cached runner is executable only when its actual bytes equal the bundle
embedded in aw. A stamp file cannot authorize different bytes. Missing, empty,
modified or symlink cache entries are repaired with a complete atomic replacement.
Remove legacy success stamps before repair so an older aw cannot trust stale state.

Existing wake state and cache directories remain supported when shared or owned
by another UID. Warn once per affected path with the exact chmod/chown command to
make it private; registration, inspection and runner startup remain available.
A read-only or unavailable shared cache warns and uses the private snapshot;
shared-cache repair never proceeds unless its legacy stamp was removed first.
Node executes a fresh process-private snapshot of the embedded, verified bundle,
created at 0700/0600 beneath the protected system temporary directory and removed
after the child exits. Replacing or widening the shared state cache cannot change
this snapshot. Refuse only unsafe permissions on the actual execution directory
or a temporary parent that lets another UID replace it. Do not gate every
ancestor mount; a storage-managed PVC root is not the execution directory.
Windows uses inherited ACLs; Unix mode checks do not establish Windows permissions.

An invalid child status JSON line increments an invalid-output count without
retaining its contents or stopping valid neighboring status delivery.

The user-paths gate qualifies the released OATS kernel against candidate aw using
the real messaging provider and an isolated passive tmux session. This kernel
wake receipt is required for the lane to pass; ordinary channel-core delivery
alone does not qualify it. This does not qualify a deployed image or Helm storage.
