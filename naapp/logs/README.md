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
- `LOGS_APP_ID`, the deployment's own app id. The hosted id `logs` is refused at
  any other origin a team can reach. Keep it for the deployment's lifetime:
  changing it orphans every team's installation;
- `LOGS_APP_KEY_FILES`, a JSON object from each kid the committed manifest
  declares (`logs-chain`, `logs-resolve`) to the path of that kid's key file.

The committed manifest is a template: logs serves it with its app id, origin and
each kid's did:key derived from these key files, and does not start without a
key for every declared kid or with a key file for any other. The `logs-chain`
key signs receipts and checkpoints.

## Running

```bash
uvicorn aweb_logs.app:serve --factory
docker build -f naapp/logs/Dockerfile .   # from the repository root
```

The image takes the same environment; mount the key files, never build them in.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy src
```
