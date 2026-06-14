# folio

`folio` is a private, agent-first document and presentation service for AWID teams. Agents authenticate with their team certificate, write append-only Markdown documents, brand them with a team theme, and mint no-login presentation links for humans.

It is seeded from the `atext` spine. The inherited auth and team-isolation contract lives in `docs/spine-sot.md`; product direction lives in `docs/sot.md`.

## What ships in this skeleton

- AWID team-certificate authentication via `aw id request --team-auth`.
- Team-scoped append-only documents and versions.
- Document-bound, version-pinned presentation links.
- Server-rendered public presentation pages with sanitized Markdown.
- Team themes with validated color/font tokens and safe raster logos.
- A single fresh-DB migration for the inherited spine schema.

Planned folio product work adds media, layout/presentation modes, video, first-class `aw folio` verbs, and declarative templates.

## Local development

```bash
uv sync
uv run uvicorn folio.api:create_app --factory --reload
```

The API defaults to `http://127.0.0.1:8765`.

## Configuration

All runtime env vars use the `FOLIO_` prefix:

- `FOLIO_DATABASE_URL` — PostgreSQL connection string.
- `FOLIO_AWID_REGISTRY_URL` — AWID registry URL, default `https://api.awid.ai`.
- `FOLIO_PUBLIC_ORIGIN` — public origin clients sign in the v2 team-auth `aud`, default `http://127.0.0.1:8765`.
- `FOLIO_DB_POOL_MIN_CONNECTIONS` — default `1`.
- `FOLIO_DB_POOL_MAX_CONNECTIONS` — default `5`.
- `FOLIO_DB_STATEMENT_CACHE_SIZE` — default `0` for PgBouncer compatibility.
- `FOLIO_AUTH_CACHE_TTL_SECONDS` — AWID auth cache TTL, default `600`.
- `FOLIO_TIMESTAMP_SKEW_SECONDS` — signed request skew window, default `300`.
- `FOLIO_DEFAULT_PRESENT_TTL_SECONDS` — default present-link TTL, default `86400`.
- `FOLIO_MAX_PRESENT_TTL_SECONDS` — max present-link TTL, default `604800`.
- `FOLIO_FREE_MAX_DOCUMENTS` — inherited free-tier cap, default `3`.
- `FOLIO_FREE_MAX_VERSIONS_PER_DOC` — inherited version cap, default `50`.

Production public origin is expected to be `https://folio.aweb.ai`.

## Using the skeleton with `aw`

From a workspace with an active AWID team certificate:

```bash
export FOLIO_ORIGIN=http://127.0.0.1:8765

aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body '{"slug":"pitch","title":"Pitch","body":"# Pitch\n\nInitial draft."}'

printf '# Pitch\n\nSecond draft.\n' > pitch-v2.md
aw id request POST "$FOLIO_ORIGIN/v1/documents/pitch/versions" --team-auth --raw \
  --body-file pitch-v2.md

aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw \
  --body '{"tokens":{"colors":{"background":"#0b1020","surface":"#ffffff","accent":"#7c5cff"},"fonts":{"body":"serif"}},"header":"Team memo","footer":"Confidential"}'

aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body '{"slug":"pitch","ttl_seconds":604800}'
```

The present response includes a public capability URL under `/present/<token>`; the URL is the human-facing permission. Revoke it when access should end:

```bash
aw id request POST "$FOLIO_ORIGIN/v1/present/<token>/revoke" --team-auth --raw
```

## Tests

```bash
make test-server
make lint
make e2e
```

`make e2e` starts local Postgres + AWID via Docker Compose, runs real `aw id request --team-auth` tests, and tears the stack down.

## Docker / Render

Build locally:

```bash
docker build -t folio-api:dev .
```

The container runs:

```bash
uvicorn folio.api:app --host 0.0.0.0 --port ${PORT:-8765}
```

`render.yaml` declares the Docker web service and the `FOLIO_` env names for a fresh Neon-backed deployment.
