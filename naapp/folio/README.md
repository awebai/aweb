# folio

`folio` is an agent-first document and presentation service for AWID teams. Agents authenticate with their team certificate, write append-only Markdown documents, brand them with a team theme, and mint no-login presentation links for humans. Documents are team-scoped; identity is the team's AWID certificate — there is no app account system.

Open source, MIT-licensed — [github.com/awebai/aweb (naapp/folio)](https://github.com/awebai/aweb/tree/main/naapp/folio).

## What it does

- AWID team-certificate authentication via `aw id request --team-auth`.
- Team-scoped append-only documents and versions.
- Document-bound, version-pinned presentation links.
- Server-rendered public presentation pages with sanitized Markdown.
- Team-scoped safe raster image uploads (`png`, `jpeg`, `gif`, `webp`) embedded with standard Markdown image syntax.
- Cloudflare Stream-backed video direct uploads and signed playback embeds.
- Team themes with validated color/font tokens and safe raster logos.
- Human and agent surfaces: `/`, `/llms.txt`, `/skills/`, `/robots.txt`.
- A single fresh-DB migration for the schema.

Planned work adds layout/presentation modes and declarative templates.

## Local development

```bash
uv sync
uv run uvicorn folio.api:create_app --factory --reload
```

The API defaults to `http://127.0.0.1:8765`.

## Configuration

All runtime env vars use the `FOLIO_` prefix; they are the shared naapp settings (`aweb_naapp.runtime.settings`) plus Folio's own:

- `FOLIO_DATABASE_URL` — PostgreSQL connection string.
- `FOLIO_AWID_REGISTRY_URL` — AWID registry URL, default `https://api.awid.ai`.
- `FOLIO_AWID_SERVICE_TOKEN` — optional AWID service credential for private-team facts and revocation reads, at least 32 bytes; provision as a secret. A denied private-team read returns `403 team_private_unreadable`; registry outages remain `503`.
- `FOLIO_PUBLIC_ORIGIN` — public origin clients sign in the v2 team-auth `aud`, default `http://127.0.0.1:8765`.
- `FOLIO_DB_POOL_MIN_CONNECTIONS` — default `1`.
- `FOLIO_DB_POOL_MAX_CONNECTIONS` — default `5`.
- `FOLIO_DB_STATEMENT_CACHE_SIZE` — default `0` for PgBouncer compatibility.
- `FOLIO_AUTH_CACHE_TTL_SECONDS` — AWID auth cache TTL, default and maximum `60`.
- `FOLIO_TIMESTAMP_SKEW_SECONDS` — signed request skew window, default and maximum `300`.
- `FOLIO_DID_AW_PROFILE` — how a certificate's did:aw is checked against its current registry key, default `observe` (admit and log); `require` refuses a mismatch.
- `FOLIO_APP_EVENTS_ORIGIN`, `FOLIO_APP_EMIT_KID`, `FOLIO_APP_EMIT_KEY_SEED_HEX` — where and with which declared key Folio emits `folio/doc.changed`. The released seed settings remain supported.
- `FOLIO_APP_KEY_FILES` — alternative JSON map from declared kids to signing-key files. The v2 template declares `folio:emit-1` (app-event) and the separate `folio:grant-read-1` (app-grant-read); every declared kid needs its key configured, even when outbound event delivery is disabled.
- `FOLIO_APP_ID` — stable deployment app id, default `folio`. See [production operations](docs/production-operations.md) for manifest filling and install re-pinning.
- `FOLIO_GIT_SHA` — the build commit `/health` reports when Render does not inject `RENDER_GIT_COMMIT`.
- `FOLIO_DEFAULT_PRESENT_TTL_SECONDS` — default read-only present-link TTL, default `86400` (one day).
- `FOLIO_MAX_PRESENT_TTL_SECONDS` — read-only present-link ceiling, default and maximum `2592000` (30 days); operators may set a lower ceiling. Explicit requests above the configured ceiling return `422`, rather than being shortened. Editable links remain limited to `300` seconds.
- `FOLIO_CLOUDFLARE_ACCOUNT_ID` — Cloudflare account id for Stream.
- `FOLIO_CLOUDFLARE_STREAM_API_TOKEN` — Stream API token for direct uploads/status.
- `FOLIO_CLOUDFLARE_STREAM_PLAYBACK_HOST` — signed playback host, for example `customer-<code>.cloudflarestream.com`.
- `FOLIO_CLOUDFLARE_STREAM_SIGNING_KEY_ID` / `FOLIO_CLOUDFLARE_STREAM_SIGNING_KEY_PEM` — key material for signed playback JWTs.
- `FOLIO_CLOUDFLARE_STREAM_DIRECT_UPLOAD_TTL_SECONDS` — default `3600`.
- `FOLIO_CLOUDFLARE_STREAM_SIGNED_PLAYBACK_TTL_SECONDS` — default `3600`.
- `FOLIO_CLOUDFLARE_STREAM_MAX_DURATION_SECONDS` — default `600`.

Production public origin is expected to be `https://folio.aweb.ai`.

## Using folio with `aw`

From a workspace with an active AWID team certificate:

```bash
export FOLIO_ORIGIN=http://127.0.0.1:8765

aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body '{"slug":"pitch","title":"Pitch","body":"# Pitch\n\nInitial draft."}'

cat > pitch-template.json <<'JSON'
{"slug":"pitch-deck","title":"Pitch deck","template":{"name":"pitch","slots":{"cover":{"title":"Pitch deck","subtitle":"Agent-authored"},"metrics":[{"label":"Teams","value":"12","caption":"pilot workspaces"}],"sections":[{"heading":"Problem","body":"Agents need durable handoffs."}],"ask":{"headline":"Ask","body":"Approve launch.","items":["Ship folio"]}}}}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body-file pitch-template.json

printf '# Pitch\n\nSecond draft.\n' > pitch-v2.md
aw id request POST "$FOLIO_ORIGIN/v1/documents/pitch/versions" --team-auth --raw \
  --body-file pitch-v2.md

aw id request POST "$FOLIO_ORIGIN/v1/documents/pitch-deck/versions/template" --team-auth --raw \
  --body '{"name":"memo","slots":{"cover":{"title":"Memo update"},"sections":[{"heading":"Status","body":"Template slots render to Markdown."}]}}'

python3 - <<'PY'
import base64, json
from pathlib import Path
Path("image-upload.json").write_text(json.dumps({
  "content_type": "image/png",
  "data_base64": base64.b64encode(Path("chart.png").read_bytes()).decode("ascii"),
}), encoding="utf-8")
PY
aw id request POST "$FOLIO_ORIGIN/v1/assets" --team-auth --raw \
  --body-file image-upload.json
# Embed the returned url in Markdown: ![chart](http://127.0.0.1:8765/assets/<asset_id>)

aw id request POST "$FOLIO_ORIGIN/v1/assets/video/direct-upload" --team-auth --raw \
  --body '{"content_type":"video/mp4","max_duration_seconds":600}'
# Upload the video bytes to the returned upload_url, then poll:
aw id request GET "$FOLIO_ORIGIN/v1/assets/<asset_id>" --team-auth --raw
# Embed the same asset URL in Markdown: ![demo video](http://127.0.0.1:8765/assets/<asset_id>)

aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw \
  --body '{"tokens":{"colors":{"background":"#0b1020","surface":"#ffffff","accent":"#7c5cff"},"fonts":{"body":"serif"}},"header":"Team memo","footer":"Confidential"}'

aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body '{"slug":"pitch","ttl_seconds":2592000}'
```

The present response includes a public capability URL under `/present/<token>`; the URL is the human-facing permission. User content under `/present/*` and `/assets/*` is marked `noindex, nofollow, noarchive` and disallowed in `robots.txt`. Revoke it when access should end:

```bash
aw id request POST "$FOLIO_ORIGIN/v1/present/<token>/revoke" --team-auth --raw
```

Agent-readable docs are served from the same app: `GET /llms.txt` for the compact contract and `GET /skills/` for task-specific skill files.

## Tests

```bash
make test-server
make lint
make e2e
```

`make e2e` starts disposable Postgres, Redis and AWID via Docker Compose and
runs Folio with the checkout's built `aw`. The install-after-mint journey also
starts the real aweb server from its locked source environment and a real custody
process, then uses a replacement grant for create/append/show. Prepare that
source environment with `uv sync --frozen --project ../../server`, build `aw`
from `../../cli/go`, and put that directory on `PATH` before running e2e.
All child processes and the disposable stack are stopped on exit.

Folio uses the in-repo `naapp-lib/` and `awid/` through its locked path sources.
Run it from an aweb checkout; separate sibling clones are unnecessary. Shared
verifier coverage lives in `naapp-lib/tests/runtime/test_team_auth_envelope.py`,
`test_team_auth_vectors.py` and `test_awid_team_cache.py`. Folio's own
`tests/test_e2e_smoke.py` exercises its integration with real AWID and `aw`.

## Docker / Render

Build locally:

```bash
docker build -t folio-api:dev .
```

The container runs:

```bash
uvicorn folio.api:app --host 0.0.0.0 --port ${PORT:-8765}
```

`render.yaml` is a template declaring the Docker web service and the `FOLIO_` env names for a fresh Neon-backed deployment. Folio's own production service is pinned in `ops/render-production.json` and operated through `make prod-*`; see [docs/production-operations.md](docs/production-operations.md).

## License

MIT. See [LICENSE](LICENSE).

### Revocation lookup bounds

Team authentication reads the complete AWID certificate history, including revoked
certificates, in pages of 200. A refresh may read at most 100 pages (20,000 records).
If more pages remain, pagination does not advance, or the response is incomplete,
the request fails closed with HTTP 503 and no partial facts enter the cache.
An expired cache entry is never used after a failed refresh. A revoked certificate
returns HTTP 401; the existing cache TTL still governs revocation freshness.
