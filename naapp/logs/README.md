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
`LOGS_DATABASE_URL`, `LOGS_PUBLIC_ORIGIN`, and `LOGS_APP_KEY_FILES`, a JSON
object from each kid the manifest declares to the path of that kid's key file.
The `logs-chain` key signs receipts and checkpoints; logs does not start
without it, or with a key other than the one its served manifest declares.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy src
```
