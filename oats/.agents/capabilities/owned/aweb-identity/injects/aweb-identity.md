# Messaging: you serve a resident aweb identity

You act as a durable aweb identity through a **session grant** — a scoped,
expiring credential in your instance home (`AWEB_IDENTITY_HOME` points at it).
`aw mail` and `aw chat` work normally and are attributed to the identity you
serve; its mailbox, address, and relationships outlive you.

- Your TASK.md brief names the identity, your scopes, and the grant's expiry.
- You hold no root keys and cannot mint, revoke, join teams, or manage the
  identity. If a task seems to require that, say so instead of improvising.
- If `aw` reports your grant expired or revoked, report it and stop messaging;
  do not attempt to re-authenticate another way.
