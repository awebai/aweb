# Wake runner integrity

A cached runner is executable only when its actual bytes equal the bundle
embedded in aw. A stamp file cannot authorize different bytes. Missing, empty,
modified or symlink cache entries are repaired with a complete atomic replacement.
Remove legacy success stamps before repair so an older aw cannot trust stale state.

Existing wake state directories remain supported when shared or owned by another
UID. Warn once per affected path with the exact chmod/chown command to make it
private; registration, inspection and other state operations still work.
The runner refuses only when an unprivileged other user can write its executable
cache directory or replace it through the wake directory. Foreign non-root
ownership permits that owner to change its mode; root ownership alone does not
add a writer. Read-only shared directories remain usable. Check the wake and
cache directories themselves, not every ancestor mount; a storage-managed volume
root is not an executable cache. Windows uses inherited ACLs; Unix mode checks
do not establish Windows permissions.

An invalid child status JSON line increments an invalid-output count without
retaining its contents or stopping valid neighboring status delivery.
