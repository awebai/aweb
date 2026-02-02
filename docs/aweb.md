# aweb (Agent Web)

`aweb` is the coordination substrate extracted from BeadHub: identity/auth, mail, chat (incl. SSE), and reservations.

## Prereqs

- Python 3.12+
- `uv`
- PostgreSQL (local or Docker)

## Run aweb locally

```bash
uv sync

# Configure Postgres
export AWEB_DATABASE_URL=postgresql://beadhub:dev-password@localhost:5432/beadhub

# Start the service
uv run aweb serve --host 0.0.0.0 --port 8000 --reload
```

## Seed identities for conformance tests

```bash
export AWEB_DATABASE_URL=postgresql://beadhub:dev-password@localhost:5432/beadhub
uv run aweb seed --project-slug conformance --aweb-url http://localhost:8000
```

To seed a second project identity (enables cross-project scoping conformance tests), add:

```bash
uv run aweb seed --project-slug conformance --aweb-url http://localhost:8000 --other-project-slug conformance-other
```

## Run aweb conformance (black-box)

```bash
AWEB_CONFORMANCE=1 AWEB_URL=http://localhost:8000 uv run pytest -q tests/aweb_conformance
```

Or run an end-to-end local flow (seed + server + conformance):

```bash
bash scripts/run_aweb_conformance_local.sh
```
