# Core app registry + app grants READ API contract (m3.1)

Status: **interface-first draft** for `default-aaaj.1` cross-validation with the
hosted gateway (ac/m4) and `aw plugin` CLI consumers.

This contract is the single read shape the gateway and CLI can stub against while
core builds the registry/grants implementation.

## Contract summary

**One query:** given a `team_id`, return the team's installed apps, granted app
scopes, and the pinned manifest digest for each install.

```http
GET /v1/apps/installed?team_id={colon-form-team-id}
```

Authorization: caller must be authorized for `team_id` (direct v2 team-auth for
CLI/local clients, or the hosted gateway's existing internal/control-plane
service authorization while acting for that team). Manifest discovery itself is
public, but this installed-app/grants list is team data.

Response `200 application/json`:

```json
{
  "team_id": "default:atext.aweb.ai",
  "apps": [
    {
      "app_id": "folio",
      "origin": "https://folio.aweb.ai",
      "app_version": "1.x",
      "manifest_version": 1,
      "digest": "sha256:4f3c...",
      "granted_scopes": ["folio:read", "folio:write"]
    }
  ]
}
```

Field rules:

- `team_id`: colon-form team id, echoed exactly after validation.
- `apps`: deterministic order by `app_id`; no pagination in v1 because this is a
  compose-time control-plane read.
- `app_id`: manifest `app.id`; unique per team install; reserved built-in CLI
  names/aliases are rejected at install.
- `origin`: manifest `app.origin`; consumers fetch
  `{origin}/.well-known/aweb-app.json` for manifest bytes.
- `app_version`: manifest `app.version` pinned at install/update.
- `manifest_version`: manifest contract version pinned at install/update.
- `digest`: `sha256:<lowercase hex>` over the **exact served manifest bytes**;
  no JSON reparse or canonicalization before hashing.
- `granted_scopes`: scopes granted to this `(team_id, app_id)` install. Grantable
  scopes are derived from the union of the manifest tools' `scopes`; the registry
  does not maintain a separate scope vocabulary.

Errors:

- `400` invalid `team_id` syntax.
- `401/403` caller is not authorized to read app grants for `team_id`.
- `500/503` registry unavailable or storage error.

## Registry/cache boundary

The registry is authoritative for **URL + digest + install + granted scopes**.
It is **not** the canonical source of manifest bytes.

Consumer flow:

1. Install/update fetches public manifest bytes from
   `{origin}/.well-known/aweb-app.json`.
2. Install/update computes sha256 over the exact bytes and records/pins the
   digest with `origin`, `app_version`, `manifest_version`, and granted scopes.
3. Gateway and CLI cache the digest-verified manifest bytes per consumer.
4. Compose/dispatch uses this read API plus the local digest-verified cache; it
   must not fetch app origins at compose time or per tool call.

A registry implementation may keep an internal byte cache as an optimization,
but origin bytes + digest verification remain canonical and the read API above
must not require consumers to trust registry-served bytes.

## Install/update semantics that affect the read contract

- Install pins the digest; app re-publish does **not** auto-upgrade an installed
  team.
- Digest mismatch on a later fetch is an update/re-install control-plane event,
  not a compose-time surprise.
- Additive verbs under already-granted scopes become usable after an explicit
  update pins the new digest; a newly introduced scope requires re-grant.
- App grants are keyed by `(team_id, app_id)` only. Connector grants and the
  connector-grant ∩ app-grant intersection stay in the hosted gateway, not core.
- Tool-name collisions are handled by consumers by app namespace (`aw <app>
  <verb>` / app-prefixed MCP tool names). Core rejects only reserved/colliding
  app ids at install.
