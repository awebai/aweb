# logs

logs.aweb.ai is an ordinary naapp. It receives an AWID team's hook events
through its hook-only `ingest` tool, checks where each event came from, and
appends it to a per-team hash chain. It signs a receipt for every event and
signs checkpoints of the chain. Only the team owner and the readers the owner
designates can read the log, each with a passkey on logs' own origin. Logs
has no edit or delete API. Retention and erasure purge an event's content and
keep the chain verifiable.

The design is [the audit substrate](../../docs/design/audit-substrate.md),
Part B. The artefacts logs signs, and the chain they commit to, are specified
in [the logs chain](../../docs/logs-chain.md).

## Configuration

logs reads its settings from `LOGS_`-prefixed environment variables:

- `LOGS_DATABASE_URL` and `LOGS_PUBLIC_ORIGIN`;
- `LOGS_CONSOLE_ORIGIN`, the plain `https` origin where designated readers enrol,
  sign in and read. It must be on a host of its own, not `LOGS_PUBLIC_ORIGIN`'s:
  readers' passkeys are bound to its hostname. A human-role act's audience must
  be this origin, since its credential is bound to the same hostname; one bound
  to any other host is refused;
- `LOGS_EMAIL_SMTP_HOST`, `LOGS_EMAIL_SMTP_PORT`, `LOGS_EMAIL_TLS` (`starttls`,
  the default, or `implicit`), `LOGS_EMAIL_USERNAME`, `LOGS_EMAIL_PASSWORD_FILE`
  (the password is read only from this file), `LOGS_EMAIL_FROM` and, for a
  private CA, `LOGS_EMAIL_CA_FILE`. logs mails each designated reader its
  enrolment link;
- `LOGS_AWID_REGISTRY_URL` and, for private team facts, `LOGS_AWID_SERVICE_TOKEN`;
- `LOGS_APP_ID`, the deployment's own app id. The hosted id `logs` is refused at
  any other origin a team can reach. Keep it for the deployment's lifetime:
  changing it orphans every team's installation;
- `LOGS_APP_KEY_FILES`, a JSON object from each kid the committed manifest
  declares (`logs-chain`, `logs-resolve`, `logs-grants`, `logs-governance`) to
  the path of that kid's key file.

The committed manifest is a template: logs serves it with its app id, origin and
each kid's did:key derived from these key files, and does not start without a
key for every declared kid or with a key file for any other. The `logs-chain`
key signs receipts and checkpoints, `logs-grants` reads the team's installation
grant and `logs-governance` signs the governance events of logs' readers.

## Running

```bash
uvicorn aweb_logs.app:serve --factory
docker build -f naapp/logs/Dockerfile .   # from the repository root
```

The image takes the same environment; mount the key files and the mail password
file, never build them in. One process serves both origins, each answered only
on its own `Host`, so it can listen on one socket or on one per origin.

While logs runs, each team whose chain has new events gets a signed checkpoint
every `LOGS_CHECKPOINT_INTERVAL_SECONDS` (default 300); an idle team gets none.

## Retention, erasure and legal holds

A team keeps every event until its owner sets a retention. A setting names an
event class, a hook or `all`, and a number of days (1 to 36500), or keeps that
class; a hook's own setting comes before the team's `all` setting. Every
`LOGS_RETENTION_INTERVAL_SECONDS` (default 3600) logs purges the events each
team's retention has expired, in bounded batches. A purge removes an event's
content, salt, signature and every projection of it, and keeps its skeleton,
so the chain still verifies and `verify` reports the purged range with the act
that purged it.

The owner sets retention, erases and holds by owner acts (`logs.retention.set`,
`logs.erase`, `logs.legal-hold.set`, `logs.legal-hold.release`), each consumed
in the transaction that applies it and recorded as a `post-governance-hook`
event in logs' own chain (`aweb_logs.governance`). A purge's act names that
record: `logs.retention.set:<event id>` or `logs.erase:<event id>`. An erasure
covers a range of the chain or every event of one actor, named by exactly its
did:aw or did:key; logs' own governance entries are never erased. An active
legal hold, on everything or on one actor, keeps retention and erasure from
purging what it holds. Shortening a retention, erasing and releasing a hold are
narrowing; keeping longer and setting a hold are widening, and only a hold is
recorded when no hook target would admit it ([hook events](../../docs/hook-events.md#the-audit-critical-gate)).
**Open (aweb-acgh.16.23):** no route delivers these acts yet; owner-act
delivery covers only the app-role and credential acts.

## Ingestion

`POST /v1/hooks/ingest` accepts the shared `AWEB-Hook DIDKey` delivery
credential, not ordinary team-auth requests. Admission checks transport,
logs' active registration, the producer's registered authority, then the
packaged catalog's payload schema before deduplication and append. Unavailable
binding or producer authority returns 503 so the sender can retry.

Client certificates are verified against a fresh controller-key read and the
runtime's shared certificate publication/revocation policy. Client quotas are
per member certificate in fixed UTC minute windows:

- `LOGS_CLIENT_EVENTS_PER_MINUTE` defaults to **30**;
- `LOGS_CLIENT_BYTES_PER_MINUTE` defaults to **131072** (128 KiB), counted from
  the canonical delivery body.

Both limits are configurable. The quota charge and append share one
transaction. Identical redelivery returns the original receipt without
spending quota; conflicting bytes return `409 event_conflict` and record a
fault without replacing the original event. Successful responses include
`event_id`, `disposition` (`appended` or `duplicate`), and `receipt`, whose
`signing_bytes` are unpadded base64url and whose `signature` is the chain
signer's detached signature.

The receiver requires an active binding. Terminal revocation delivery remains
subject to the paired producer/receiver contract amendment; it has no special
admission exception here.

When a local governance effect and its chain entry must commit together, use
`aweb_logs.ledger.append_on(tx, signer, ...)` with the caller's transaction.
`append(db, signer, ...)` opens its own transaction and delegates to that same
implementation. The caller passes the shared producer's verified immutable
event bytes after ordinary production authorization and widening admission;
self-append does not waive those checks or deliveries owed to other targets.
A later delivery of those bytes returns the original receipt.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy src
```
