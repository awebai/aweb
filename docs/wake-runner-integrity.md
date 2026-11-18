# Wake runner integrity

A cached runner is executable only when its actual bytes equal the bundle
embedded in aw. A stamp file cannot authorize different bytes. Missing, empty,
modified or symlink cache entries are repaired with a complete atomic replacement.
Remove legacy success stamps before repair so an older aw cannot trust stale state.

Runner state directories must be owned by the current user and inaccessible for
writing by other users on Unix. Refusal explains how to select a private state
directory. Windows uses the platform's inherited directory ACLs; Unix mode checks
do not establish Windows permissions.

An invalid child status JSON line increments an invalid-output count without
retaining its contents or stopping valid neighboring status delivery.
