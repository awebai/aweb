---
name: create-from-template
description: Use when an agent needs to create or append a folio document from a built-in declarative template: pitch, memo, or metrics. This is for USING folio, not changing server code.
---

# Create a folio document from a built-in template

Use this when the human wants a structured deck, memo, or metrics page and you
want folio to render schema-validated slots to ordinary Markdown before storage.
The stored document is still append-only Markdown; templates are just a safer
input shape for common layouts.

## Prerequisites

Run from a workspace with an active AWID team certificate:

```bash
aw workspace status
aw id cert show
export FOLIO_ORIGIN=https://folio.aweb.ai
```

For local development, use `http://127.0.0.1:8765` instead.

## Template schema

All template requests use:

```json
{"name":"<pitch|memo|metrics>","slots":{}}
```

Minimal pitch selector shape: `{"name":"pitch","slots":{"cover":{"title":"Deck"},"sections":[]}}`.

Built-ins:

- `pitch`: cover/metrics/sections/ask
- `memo`: cover/sections
- `metrics`: cover/metrics

Slot fields:

- `cover`: `title` required; optional `subtitle`, `eyebrow`.
- `metrics`: array of objects with `label` required, `value` required, optional `caption`.
- `sections`: array of objects with `heading` required, optional `body` Markdown.
- `ask`: object with optional `headline`, `body` Markdown, `items` array of strings.

Unsupported templates, slots, fields, or bad shapes fail closed with 422.

## Pitch body shape

```bash
cat > pitch-template.json <<'JSON'
{
  "slug": "pitch",
  "title": "Pitch",
  "template": {
    "name": "pitch",
    "slots": {
      "cover": {
        "title": "Aweb Folio",
        "subtitle": "Agent-authored documents and presentations",
        "eyebrow": "Private by capability link"
      },
      "metrics": [
        {"label": "Teams", "value": "12", "caption": "pilot workspaces"},
        {"label": "Time to share", "value": "<1 min", "caption": "after draft approval"}
      ],
      "sections": [
        {"heading": "Problem", "body": "Agents need durable handoffs that humans can read without logging in."},
        {"heading": "Solution", "body": "Use append-only Markdown, team themes, media, and no-login present links."}
      ],
      "ask": {
        "headline": "Ask",
        "body": "Approve launch and send the presentation link.",
        "items": ["Ship folio", "Watch deploy", "Follow up with feedback"]
      }
    }
  }
}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body-file pitch-template.json
```

## Memo body shape

```bash
cat > memo-template.json <<'JSON'
{
  "slug": "team-memo",
  "title": "Team memo",
  "template": {
    "name": "memo",
    "slots": {
      "cover": {"title": "Team memo", "subtitle": "Weekly update"},
      "sections": [
        {"heading": "Status", "body": "Green — final milestone is in review."},
        {"heading": "Risks", "body": "Keep present links private and noindex."}
      ]
    }
  }
}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body-file memo-template.json
```

## Metrics body shape

```bash
cat > metrics-template.json <<'JSON'
{
  "slug": "launch-metrics",
  "title": "Launch metrics",
  "template": {
    "name": "metrics",
    "slots": {
      "cover": {"title": "Launch metrics"},
      "metrics": [
        {"label": "Documents", "value": "3", "caption": "free-tier cap"},
        {"label": "Versions", "value": "50", "caption": "per document"}
      ]
    }
  }
}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body-file metrics-template.json
```

## Append a template-generated version

Use the template body without `slug`/`title` against the append endpoint:

```bash
cat > pitch-v2-template.json <<'JSON'
{
  "name": "memo",
  "slots": {
    "cover": {"title": "Pitch update"},
    "sections": [
      {"heading": "Changes", "body": "Updated the ask and launch metrics."}
    ]
  }
}
JSON
aw id request POST "$FOLIO_ORIGIN/v1/documents/pitch/versions/template" --team-auth --raw \
  --body-file pitch-v2-template.json
```

## Present the generated document

```bash
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body '{"slug":"pitch","ttl_seconds":86400}'
```

The returned `/present/<token>` page uses the same theme, layout, sanitizer, and
noindex protections as any other folio document.
