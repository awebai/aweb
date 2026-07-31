# Session admission leases

> **Status: shipped experimental primitive.** Use it only through the explicit
> commands below; no aweb path or external orchestrator acquires it
> automatically.

Session admission leases are a server-enforced accident-prevention primitive for
one authenticated principal. When a live lease exists, a different per-session
key cannot acquire or renew it until its TTL expires. The server stores only a
SHA-256 hash of the session key.

**Nothing acquires this lease automatically today.** Aweb does not own external
session lifecycle, and no portable start/end association currently keeps a
lease honest for an independently managed process. An orchestrator may integrate
these explicit commands, but the primitive does not automatically prevent
concurrent starts.

Exercise it explicitly:

```bash
aw session lease acquire  --session-id <run-id> --session-key <32+-char-secret> --ttl-seconds 300
aw session lease renew    --session-id <run-id> --session-key <32+-char-secret> --ttl-seconds 300
aw session lease status
aw session lease release  --session-id <run-id> --session-key <32+-char-secret>
```

Do not put reusable credentials in the session key. Avoid shell history when
supplying it. A live lease cannot be silently preempted. Early takeover is an
explicit audited operation and requires a reason:

```bash
aw session lease takeover --session-id <new-run-id> --session-key <new-secret> \
  --ttl-seconds 300 --reason "operator-confirmed migration"
```

This is **not fencing or a security boundary**. Protected writes do not check the
lease generation. An exact copy of the principal signing key can still
authenticate as that principal; aweb has no per-device credentials or
per-device revocation. Migration therefore relies on procedure plus admission
control, not revocation. True fencing requires a run-scoped credential checked
at every protected write.
