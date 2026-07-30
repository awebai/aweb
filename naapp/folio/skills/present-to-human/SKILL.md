---
name: present-to-human
description: Use when an agent needs to show a human an folio document: mint a document-bound capability link with POST /v1/present, open the returned URL for the human, print it as fallback, and optionally revoke it later. This is for USING folio, not changing server code.
---

# Present an folio document to a human

Use this when a team document is ready for a human to read. The agent mints a
capability URL for one pinned document version. The human opens a server-rendered
HTML page; no account or team certificate is needed for the audience.

## Prerequisites

Run from a workspace with an active AWID team certificate:

```bash
aw workspace status
aw id cert show
export FOLIO_ORIGIN=https://folio.aweb.ai
```

For local development, use `http://127.0.0.1:8765` instead.

## 1. Confirm the document/version

```bash
aw id request GET "$FOLIO_ORIGIN/v1/documents/<slug>" --team-auth --raw
aw id request GET "$FOLIO_ORIGIN/v1/documents/<slug>/versions" --team-auth --raw
```

## 2. Mint the present link

Use the document slug. `version` is optional; omit it to pin the current latest.
`ttl_seconds` is optional and capped by server config.

```bash
cat > present.json <<'JSON'
{"slug":"<slug>","version":1,"ttl_seconds":86400}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body-file present.json \
  | tee present-response.json
```

Expected response:

```json
{"token":"<opaque-token>","url":"https://folio.aweb.ai/present/<token>","expires_at":"<timestamp>"}
```

## 3. Open it for the human

Your agent opens the view for the human. Also print the URL as fallback. If the
environment is headless or the opener is unavailable, printing is enough.

```bash
PRESENT_URL=$(jq -r '.url' present-response.json)
if command -v open >/dev/null 2>&1; then
  open "$PRESENT_URL" || true
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$PRESENT_URL" || true
fi
printf 'Presented view: %s\n' "$PRESENT_URL"
```

## 4. Revoke when needed

```bash
TOKEN=$(jq -r '.token' present-response.json)
aw id request POST "$FOLIO_ORIGIN/v1/present/$TOKEN/revoke" --team-auth --raw
```

Expected response:

```json
{"revoked":true}
```

Unknown, expired, and revoked public tokens return 404. The public page does not
expose team id, document id, version metadata, creator identity, or certificate
fields.
