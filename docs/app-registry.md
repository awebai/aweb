# App registry and team grants

Status: **current experimental public contract**. Owner: the aweb OSS server
extension surface. The implementation lives in `server/src/aweb/app_registry.py`
and `server/src/aweb/routes/apps.py`; the schema is added by
`server/src/aweb/migrations/aweb/008_app_registry_grants.sql` and
`009_app_events.sql`. HTTP behavior is covered by
`server/tests/test_app_registry_http.py`.

This registry is optional and is not part of aweb's default communication
journey. It records app metadata, a digest pin, and per-team granted scopes. It
is not an app marketplace, a source of canonical manifest bytes, or a promise
that a hosted gateway dynamically composes tools.

## Relationship to app manifests

The manifest format and interpretation rules live in
[`app-manifest.md`](app-manifest.md). An app publishes exact bytes at:

```text
<origin>/.well-known/aweb-app.json
```

The registry stores the app id, origin, app version, manifest version, and
`sha256:<lowercase hex>` digest of those exact bytes. It does **not** fetch the
origin or verify that the supplied digest matches the served manifest. The
installer is responsible for fetching, validating, and hashing the bytes before
calling the install route. Consumers must compare cached bytes with the recorded
digest; a registry row is not evidence that this verification occurred.

## Install or update

```http
POST /v1/apps/install
```

Authentication: normal team-certificate auth. The authenticated certificate
selects the team; there is no `team_id` in the request body.

```json
{
  "app_id": "folio",
  "origin": "https://folio.example",
  "app_version": "1.4.0",
  "manifest_version": 1,
  "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
  "granted_scopes": ["folio:read", "folio:write"],
  "events": [
    {
      "type": "doc.changed",
      "default_delivery_intent": "wake",
      "description": "A document changed."
    }
  ],
  "event_emitters": [
    {"kid": "emit-2026-06", "did_key": "did:key:z6Mk..."}
  ]
}
```

The response is the installed-app projection:

```json
{
  "app_id": "folio",
  "origin": "https://folio.example",
  "app_version": "1.4.0",
  "manifest_version": 1,
  "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
  "granted_scopes": ["folio:read", "folio:write"]
}
```

Current rules:

- `app_id` is lower-case, path-safe, and cannot collide with a reserved `aw`
  top-level command id. The shared reserved set is
  `test-vectors/reserved-app-ids-v1.json`.
- One app id has one origin across this registry. Reusing an app id for another
  origin conflicts.
- An origin is an `http` or `https` origin only: no userinfo, path, query, or
  fragment. Production operators should require HTTPS at their policy boundary;
  the experimental OSS route permits HTTP for local deployments.
- Reinstalling the same team/app/origin explicitly replaces its digest,
  app-version projection, scopes, event declarations, and active emit-key rows
  supplied for the new digest. Publishing new bytes at the origin does not
  silently update an installation.
- Scopes are normalized and stored. The server does not fetch the manifest to
  prove that the requested scopes are the union of `tools[].scopes`.
- Event declarations are app-local names. Emit keys are public `did:key`
  material; private emit keys never belong in a manifest or install request.
- No public uninstall route ships today. Do not document uninstall or automatic
  upgrade as current behavior.

## Read installed apps and grants

```http
GET /v1/apps/installed?team_id=<name:domain>
```

Authentication: team-certificate auth for the requested team. The source also
supports a trusted host-integration read context, but that internal header
scheme is not a portable third-party protocol; independent clients use team
auth.

Response:

```json
{
  "team_id": "default:example.com",
  "apps": [
    {
      "app_id": "folio",
      "origin": "https://folio.example",
      "app_version": "1.4.0",
      "manifest_version": 1,
      "digest": "sha256:4f3c000000000000000000000000000000000000000000000000000000000000",
      "granted_scopes": ["folio:read", "folio:write"]
    }
  ]
}
```

- Apps are ordered by `app_id`.
- A team with no installs receives `200` with `apps: []`.
- V1 has no pagination.
- `400` means invalid `team_id`; `401`/`403` means the caller cannot read that
  team; storage failures are server errors.

## Cache and consumer boundary

The registry is authoritative for its own stored tuple
`(team_id, app_id, origin, digest, granted_scopes)`. Canonical manifest bytes
remain at the app origin and in each consumer's digest-verified cache.

A consumer may cache the installed-app read through transient failures, but it
must keep the digest and origin together and must never reinterpret different
bytes under the old digest. Connector grants, human accounts, billing, and a
hosted operator's tool-composition policy are outside this OSS contract.

## Lifecycle limits

This surface is experimental: route and schema changes require corresponding
source tests and documentation review. The digest pin and explicit-update rule
are compatibility constraints. App installation is not required for mail, chat,
events from built-in coordination mutations, or self-hosting the core
communication service.
