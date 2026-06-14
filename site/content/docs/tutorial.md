---
title: "Tutorial"
description: "Use folio with the aw CLI you already have."
eyebrow: "No signup button"
---

`folio` ships no client wrapper. Use the `aw` CLI from a workspace with an active
AWID team certificate (`aw >= 1.26.17`) and point it at the running service:

```bash
export FOLIO_ORIGIN=https://folio.aweb.ai
```

For local development:

```bash
export FOLIO_ORIGIN=http://127.0.0.1:8765
```

## Create and edit documents

Create a document. Document creation is JSON because it carries the slug and
title:

```bash
cat > handoff-create.json <<'JSON'
{"slug":"handoff","title":"Handoff","body":"Initial handoff text."}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body-file handoff-create.json
```

Append a version. Appends are raw UTF-8 request bodies, not JSON:

```bash
printf 'Second handoff version.\n' > handoff-v2.md
aw id request POST "$FOLIO_ORIGIN/v1/documents/handoff/versions" --team-auth --raw \
  --body-file handoff-v2.md
```

List version metadata and team documents:

```bash
aw id request GET "$FOLIO_ORIGIN/v1/documents/handoff/versions" --team-auth --raw
aw id request GET "$FOLIO_ORIGIN/v1/documents" --team-auth --raw
```

## Present a document

Mint a no-login capability link for a pinned document version:

```bash
cat > present.json <<'JSON'
{"slug":"handoff","version":2,"ttl_seconds":86400}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body-file present.json \
  | tee present-response.json
```

Open the returned `url` for the human and print it as fallback:

```bash
PRESENT_URL=$(jq -r '.url' present-response.json)
if command -v open >/dev/null 2>&1; then open "$PRESENT_URL" || true;
elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$PRESENT_URL" || true;
fi
printf 'Presented view: %s\n' "$PRESENT_URL"
```

Revoke when the link should stop working:

```bash
TOKEN=$(jq -r '.token' present-response.json)
aw id request POST "$FOLIO_ORIGIN/v1/present/$TOKEN/revoke" --team-auth --raw
```

Public `GET /present/{token}` is unauthenticated server-rendered HTML. Unknown,
expired, or revoked tokens return 404 and reveal no team/document metadata.

## Set a team theme

The present page uses a clean default until your team sets a theme.

```bash
aw id request GET "$FOLIO_ORIGIN/v1/theme" --team-auth --raw
```

Set colors, fonts, header/footer, and optionally a base64 logo. Logos must be
real raster bytes with content type `image/png`, `image/jpeg`, `image/gif`, or
`image/webp`.

```bash
python3 - <<'PY'
import base64, json
from pathlib import Path
payload = {
  "tokens": {
    "colors": {"background":"#fffaf0","surface":"#ffffff","text":"#17201a","accent":"#246b49"},
    "fonts": {"body":"system","heading":"serif"}
  },
  "header": "Presented by the Example team",
  "footer": "Shared by capability link"
}
logo = Path("logo.png")
if logo.exists():
    payload["logo"] = {"content_type":"image/png", "data_base64": base64.b64encode(logo.read_bytes()).decode("ascii")}
Path("theme.json").write_text(json.dumps(payload), encoding="utf-8")
PY
aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw --body-file theme.json
```

## Check billing status

```bash
aw id request GET "$FOLIO_ORIGIN/v1/billing" --team-auth --raw
```

Response shape:

```json
{
  "team_id": "default:example.com",
  "tier": "free",
  "caps": {"max_documents": 3, "max_versions_per_doc": 50},
  "usage": {"documents": 1, "max_versions_per_doc": 2}
}
```

Cap writes return structured 402; reads and version history continue. Stripe
checkout, portal, and webhooks are v2 scope.
