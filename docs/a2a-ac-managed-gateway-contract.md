# AC-Managed A2A Gateway Contract

Status: normative contract for `aweb-aaqa.14.1`.

This contract extends [`a2a.md`](a2a.md) and
[`a2a-awid-publication-contract.md`](a2a-awid-publication-contract.md). It
replaces the abandoned manual Render tarball lane with the product path for
hosted A2A routes: AC is the control plane; `aweb-a2a-gw` is the data plane.

## Invariants

- Hosted customers do not upload `.aw` workspace tarballs, hand-write gateway
  YAML, or manage gateway identity files.
- The hosted A2A gateway is server-readable plaintext infrastructure. It must
  not be described as E2EE.
- No route is called `verified`, `AWID-backed`, or `authorized for address`
  until AC and the gateway enforce active AWID publication, active delegation
  when required, card digest match, expiry, revocation, and key-history checks.
- Self-custodial private keys never leave the operator/agent device. A hosted
  gateway can bridge self-custodial identities only through explicit delegation.
- AC-managed route config is the hosted source of truth. Static YAML remains
  local-development and self-host-only input.
- Route disable, publication mismatch, missing authority, stale config, or
  gateway identity failure all fail closed.
- The banked `a2a-gw-v1.26.9` image and release lane remain useful
  infrastructure, but the manual `a2a.aweb.ai` Render secret/tarball deployment
  is not the product path.

## Product Architecture

```text
AC control plane
  owns route records, card config, auth policy, verification state,
  gateway identity custody, and AWID publication/delegation state

aweb-a2a-gw data plane
  authenticates as the hosted gateway service
  fetches AC route config
  serves A2A cards and JSON-RPC
  sends durable aweb bridge messages through its gateway identity
```

AC must be able to stop or disable all public hosted A2A routes without
requiring access to Render shell or to a local gateway workspace.

## Route Data Model

AC stores one route record per exposed A2A address. Minimum fields:

| Field | Required | Notes |
|---|---:|---|
| `route_id` | yes | Opaque stable route id used in `/a2a/agents/{route_id}`. |
| `host` | yes | Public gateway host, e.g. `a2a.aweb.ai`. |
| `address` | yes | Target aweb address, e.g. `a2a.aweb.ai/research`. |
| `target_kind` | yes | `aweb_address` in v1. Future values need contract review. |
| `mode` | yes | `mail` in v1. |
| `enabled` | yes | Disabled routes fail closed. |
| `root_behavior` | yes | `none`, `default_for_host`, or `router_member`. |
| `card_name` | yes | A2A Agent Card `name`. |
| `card_description` | yes | A2A Agent Card `description`. |
| `card_provider_name` | yes | Provider organization. |
| `card_provider_url` | yes | Provider URL. |
| `card_version` | yes | Agent Card version. |
| `skills_json` | yes | Structured skill list; validated before persistence. |
| `auth_mode` | yes | `none`, `static_api_key`, or later reviewed modes. |
| `rate_limit` | yes | Per route/caller rate policy. |
| `max_message_bytes` | yes | Request body/task text bound. |
| `max_concurrent_tasks` | yes | Per route concurrency bound. |
| `task_ttl_seconds` | yes | Task expiry. |
| `response_timeout_seconds` | yes | Wait timeout for non-`returnImmediately` calls. |
| `gateway_identity_id` | yes | AC reference to the hosted gateway identity. |
| `verification_tier` | yes | `unsigned`, `local_configured`, `awid_published`, `delegated`, `mismatch`, `expired`, or `revoked`. |
| `card_digest` | no | Required once served card material is active. |
| `card_revision` | no | Required for AWID publication. |
| `publication_assertion_id` | no | AWID publication id. |
| `publication_digest` | no | Digest of signed publication assertion when available. |
| `publication_status` | yes | `not_published`, `active`, `mismatch`, `expired`, `revoked`, `error`. |
| `delegation_id` | no | Required when gateway identity differs from address authority. |
| `delegation_digest` | no | Required when delegation id is present. |
| `delegation_status` | yes | `not_required`, `active`, `missing`, `mismatch`, `expired`, `revoked`, `error`. |
| `created_by` / `updated_by` | yes | User/service actor ids. |
| `created_at` / `updated_at` | yes | Audit timestamps. |
| `disabled_at` / `disabled_reason` | no | Required when disabled. |

Route records must not store raw private keys, controller keys, user API keys,
or raw A2A caller plaintext. Auth secrets, when needed, use the existing AC
secret-storage pattern and are referenced by secret id.

## Gateway Identity Custody

Hosted AC deployments use a dedicated gateway identity. It must not reuse a
human agent key.

AC owns:

- gateway identity creation or lookup;
- gateway team/service certificate issuance;
- encrypted storage of gateway signing material using the existing hosted
  custodial key protection;
- rotation and compromise response;
- runtime credentials that let `aweb-a2a-gw` fetch config and sign/send bridge
  messages as the gateway identity.

AC must not deliver namespace controller keys to Render or to the gateway data
plane. Self-custodial route delegation is a signed AWID delegation, not private
key sharing.

Missing or unusable gateway signing material fails closed:

- route creation cannot mark the route active;
- gateway config fetch marks route unavailable;
- `/health` reports identity/config failure;
- no verified copy is shown.

## Runtime Config API

Hosted `aweb-a2a-gw` starts with minimal deployment configuration:

```yaml
mode: ac_managed
ac_base_url: https://app.aweb.ai
gateway_id: gw_...
registry_url: https://api.awid.ai
```

The exact transport can be environment variables, a minimal YAML file, or a
small service credential file. It must not contain route definitions or `.aw`
workspace state in the hosted product path.

The gateway calls an AC endpoint to fetch its runtime config. Minimum response:

```json
{
  "gateway_id": "gw_...",
  "gateway_identity": "did:aw:...",
  "aweb_url": "https://app.aweb.ai",
  "registry_url": "https://api.awid.ai",
  "config_revision": "2026-06-08T15:00:00Z:12",
  "expires_at": "2026-06-08T15:05:00Z",
  "routes": [
    {
      "route_id": "research",
      "host": "a2a.aweb.ai",
      "address": "a2a.aweb.ai/research",
      "enabled": true,
      "card": {},
      "auth": {},
      "limits": {},
      "awid_publication": {
        "required": true,
        "status": "active",
        "card_digest": "sha256:...",
        "publication_assertion_id": "pub_...",
        "delegation_id": "del_..."
      }
    }
  ]
}
```

The gateway must validate the fetched config before serving it:

- route ids are slug/path safe;
- card URLs and RPC URLs match the configured host/path convention;
- card digest matches generated card bytes when AWID publication is required;
- disabled routes are not served as active;
- expired config is not used for new tasks;
- auth/rate limits are present for public routes.

Stale config behavior:

- If AC is temporarily unreachable and the cached config is unexpired, the
  gateway may continue serving cached config.
- If cached config is expired, the gateway must stop accepting new tasks and
  `/health` must report unhealthy or degraded according to the contract.
- A disabled route must be removed or fail closed as soon as a fresh config
  marks it disabled.

## Gateway Health

Hosted `/health` must include at least:

- build release tag and git sha;
- aweb/gateway version;
- AWID registry reachability and compatibility floor;
- AC config fetch status;
- config revision and expiry;
- gateway identity status;
- route counts by state: active, disabled, verification_error, expired.

Health must be `503` when:

- AWID registry is unreachable or below the required version floor;
- AC config is missing or expired;
- gateway identity is missing/unusable;
- route config cannot be validated.

## AWID Publication and Delegation

AC-managed routes use
[`a2a-awid-publication-contract.md`](a2a-awid-publication-contract.md) for all
publication/delegation bytes and conflict codes.

AC responsibilities:

- compute served card digest from generated card bytes;
- publish/update/revoke AWID A2A publication assertions when authority exists;
- publish/update/revoke bridge delegation assertions when gateway identity
  differs from address authority;
- store assertion ids/digests/status;
- re-fetch and verify active AWID state before showing verified route state;
- clear or downgrade verified state when publication/delegation expires,
  mismatches, or is revoked.

No route can be customer-visible as verified unless the active served card
matches the active AWID publication digest.

## Dashboard and API Surface

Minimum hosted route management:

- list routes and verification state;
- create route for an existing hosted/self-custodial address;
- edit card metadata and skills;
- configure auth/rate/task limits;
- enable/disable route;
- publish/republish/revoke AWID assertion when authority is present;
- show plaintext hosted gateway boundary.

Permission rules:

- users can manage only routes for identities/teams they control;
- self-custodial delegation requires the self-custodial signer to authorize;
- hosted-custodial publication uses hosted session authority;
- AC operators can disable public routes for abuse/safety but cannot silently
  create a verified claim without authority.

## Release and Migration Rules

- AC schema changes use new ordered migrations.
- AWID migration changes use new ordered migrations and never edit shipped
  migrations.
- Release order is AWID first when AWID schema/API changes, then AC, then
  gateway image/runtime as needed, then site/docs copy.
- The manual Render tarball lane remains stopped and must not be presented as
  the hosted customer workflow.

## Required Tests

Release-blocking tests for this slice:

1. AC route CRUD stores no private key or caller plaintext in route config.
2. Route disable fails closed at the gateway.
3. Gateway fetches AC config and serves cards without static production YAML or
   `.aw` tarball state.
4. Gateway rejects expired/malformed AC config.
5. `/health` reports AC config status, gateway identity status, and AWID
   compatibility.
6. AWID publication mismatch prevents verified state and blocks verified copy.
7. Missing delegation for delegated route fails closed.
8. Gateway identity missing/unusable fails closed.
9. Docker e2e with real AC + aweb + AWID provisions a route, sends
   `SendMessage`, receives real aweb reply, and completes `GetTask`.
10. Public wording guardrail blocks `verified`, `AWID-backed`,
    `authorized for address`, and `E2EE` claims before live gates.

## Review Gates

- Athena reviews this contract and any change to A2A/AWID protocol semantics.
- Mia reviews implementation-readiness and every backend/runtime slice.
- Hestia reviews release sequencing before deploy.
- Olivia reviews public site/dashboard copy before any customer-facing A2A
  claim changes.
