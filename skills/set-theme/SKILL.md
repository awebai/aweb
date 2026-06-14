---
name: set-theme
description: Use when an agent needs to brand folio presentation pages for its team: read or update GET/PUT /v1/theme with colors, fonts, header/footer, and an optional base64 raster logo. This is for USING folio, not changing server code.
---

# Set an folio team theme

Use this when a team wants its `/present/<token>` pages to carry brand colors,
fonts, a logo, or header/footer text. Theme is team-scoped and applies when
public present pages render.

## Prerequisites

Run from a workspace with an active AWID team certificate:

```bash
aw workspace status
aw id cert show
export FOLIO_ORIGIN=https://folio.aweb.ai
```

For local development, use `http://127.0.0.1:8765` instead.

## 1. Read the current theme

```bash
aw id request GET "$FOLIO_ORIGIN/v1/theme" --team-auth --raw
```

An empty theme returns default tokens plus null logo/header/footer fields.

## 2. Build a theme request

Supported token groups:

- `colors`: `background`, `surface`, `text`, `muted`, `border`, `accent`
- `fonts`: `body`, `heading` with values `system`, `serif`, or `mono`
- `header`, `footer`: optional strings
- `logo`: optional base64 raster image with content type `image/png`,
  `image/jpeg`, `image/gif`, or `image/webp`
- `clear_logo`: set true to remove the current logo

Logo bytes must match the declared content type and be no larger than 256 KiB.
SVG and HTML are rejected.

```bash
python3 - <<'PY'
import base64, json
from pathlib import Path

payload = {
    "tokens": {
        "colors": {
            "background": "#fffaf0",
            "surface": "#ffffff",
            "text": "#17201a",
            "muted": "#5f685f",
            "border": "#ded6c4",
            "accent": "#246b49",
        },
        "fonts": {"body": "system", "heading": "serif"},
    },
    "header": "Presented by the Example team",
    "footer": "Shared by capability link",
}
logo = Path("logo.png")
if logo.exists():
    payload["logo"] = {
        "content_type": "image/png",
        "data_base64": base64.b64encode(logo.read_bytes()).decode("ascii"),
    }
Path("theme.json").write_text(json.dumps(payload), encoding="utf-8")
PY
```

## 3. Set the theme

```bash
aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw --body-file theme.json
```

The response includes sanitized `tokens`, optional `logo_asset_id` and
`logo_url`, `header`, `footer`, and `updated_at`. Unsupported token keys or
unsafe values are ignored; invalid logo input returns 400.

## 4. Verify with a present link

Mint or open any existing present link. The public page should render with the
team's current theme. The document markdown itself is still sanitized and
server-rendered.
