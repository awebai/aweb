# awid.ai — Identity Resolution Service SOT

## Purpose

awid.ai is the standalone identity resolution service for the aweb ecosystem.
It owns the full resolution chain:

```
human-readable address → did:aw → did:key
  (namespace/name)       (stable ID)  (current key)
```

Identity resolution is a separate concern from coordination. An independent,
auditable identity service strengthens the trust model and enables adoption
beyond aweb.

## Relationship to aweb

awid.ai imports from the `aweb` package. It is a deployment of aweb's identity
code, not a fork or copy.

The canonical identity model lives in [id-sot.md](id-sot.md). That document
defines agents, workspaces, identity classes, custody modes, aliases, and
addresses. This document does not redefine them.

This document defines:

- what awid.ai owns
- what stays in aweb
- the interface contract between them
- schema changes from the current embedded model
- the self-hosted story

## What awid.ai Owns

awid.ai is the authority for:

- **DID registry**: mapping `did:aw` to current `did:key`, with an append-only
  audit log of key changes
- **Namespaces**: mapping DNS domains to controller DIDs, with DNS TXT
  verification
- **Addresses**: mapping `namespace/name` to `did:aw` with reachability metadata
- **Replacements**: recording DID transitions when an address is reassigned to a
  new identity

### Tables

| Table | Purpose |
|-------|---------|
| `did_aw_mappings` | did:aw → current did:key + server_url |
| `did_aw_log` | Append-only audit log of key changes |
| `namespaces` | domain → controller_did (DNS-verified) |
| `addresses` | namespace/name → did:aw + reachability |
| `replacements` | old_did → new_did + controller proof |

### Endpoints

DID registry:

- `POST /v1/did` — register stable identity
- `GET /v1/did/{did_aw}/key` — resolve current key (+ signed log head)
- `GET /v1/did/{did_aw}/head` — log head metadata
- `GET /v1/did/{did_aw}/full` — full mapping (DIDKey auth required)
- `GET /v1/did/{did_aw}/log` — full audit log
- `PUT /v1/did/{did_aw}` — rotate key / update server

Namespaces:

- `POST /v1/namespaces` — register namespace (DNS TXT verification)
- `GET /v1/namespaces/{domain}` — query namespace
- `GET /v1/namespaces` — list namespaces
- `DELETE /v1/namespaces/{domain}` — soft-delete

Addresses:

- `POST /v1/namespaces/{domain}/addresses` — register address
- `GET /v1/namespaces/{domain}/addresses/{name}` — resolve address
- `GET /v1/namespaces/{domain}/addresses` — list addresses in namespace
- `PUT /v1/namespaces/{domain}/addresses/{name}` — update current key
- `DELETE /v1/namespaces/{domain}/addresses/{name}` — soft-delete
- `POST /v1/namespaces/{domain}/addresses/{name}/reassign` — reassign to new identity

### Authentication

All mutating endpoints use DIDKey signature-based auth:

```
Authorization: DIDKey <did:key:z...> <base64_signature>
X-AWEB-Timestamp: <ISO8601>
```

Signing payload: `{timestamp}\n{method}\n{path}`

Timestamp skew tolerance: ±300 seconds.

Read endpoints are public and rate-limited.

## What Stays in aweb

aweb retains:

- **Agent lifecycle**: the `agents` table, bootstrap, retire, replace flows
- **Custody**: key encryption, decryption, signing on behalf of custodial agents
  (`aweb.awid.custody`)
- **Identity contracts**: validation logic (`aweb.awid.contract`)
- **Message routing**: resolving addresses to local agents for delivery
  (`address_scope.py`)
- **Delivery metadata**: enriching messages with address and replacement context
  (`aweb.awid.replacement`)
- **Stable ID derivation**: deterministic, cached in agents table
  (`aweb.awid.stable_id`)
- **Identity primitives**: key generation, DID encoding, signing, verification
  (`aweb.awid.did`, `aweb.awid.signing`) — used locally by both aweb and
  awid.ai

aweb does not serve DID, namespace, or address endpoints when configured to use
an external awid.ai instance.

## What Stays in aweb-cloud

aweb-cloud retains:

- **Managed namespaces**: tracks which namespaces aweb-cloud custodially
  controls, including encrypted controller keys. From awid.ai's perspective
  these are ordinary DNS-verified namespaces — the custodial relationship is
  internal to aweb-cloud.
- **User accounts, billing, organizations, projects**
- **Auth bridge, tier limits**

## Namespace Model

From awid.ai's perspective, every namespace is a domain controlled by a DID,
verified via DNS TXT record. There is no "managed" vs "dns_verified" type
distinction at the awid.ai level.

The current aweb schema has `namespace_type` and `scope_id` fields on
`dns_namespaces`. These are implementation details of the embedded model:

- `namespace_type` mapped to custody mode (who holds the controller key)
- `scope_id` linked managed namespaces to projects

In awid.ai:

- All namespaces have a `controller_did` (NOT NULL)
- There is no `namespace_type` or `scope_id`
- aweb-cloud tracks the custodial relationship in its own `managed_namespaces`
  table

A managed namespace like `myproject.aweb.ai` is registered at awid.ai like
any other namespace. The DNS TXT record proves the controller DID. aweb-cloud
holds the controller private key and signs registration requests on behalf of
the project.

## Replacement Model

Replacement announcements record when a public address is reassigned from one
permanent identity to another. The current aweb schema references
`agents.agent_id` for old and new agents.

In awid.ai, replacements reference DIDs only:

- `old_did`: the departing identity's DID
- `new_did`: the successor identity's DID
- `controller_did`: the namespace controller that authorized the reassignment
- `controller_signature`: proof of authorization

aweb tracks the agent_id ↔ did mapping locally.

## Configuration

aweb and aweb-cloud use `AWID_REGISTRY_URL` to configure the identity service:

| Value | Behavior |
|-------|----------|
| `https://api.awid.ai` (default) | Uses public awid.ai. Identity routes not mounted locally. |
| `https://my-awid.example.com` | Uses private awid.ai instance. |
| `local` | Embedded mode. Identity routes mounted locally. For air-gapped deployments. |

## Graceful Degradation

When awid.ai is unreachable:

- **DID registration, rotation, namespace, address operations**: fail. Retry
  later. These are infrequent.
- **DID resolution by verifiers**: falls back to TOFU. The verification protocol
  defines `OK_DEGRADED` for registry unavailability.
- **Address-based message routing**: degrades. aweb can use cached resolutions
  but fresh lookups fail.
- **Coordination and messaging**: unaffected for alias-based addressing.
  `did:key` is self-certifying.

## Implementation

awid.ai is a thin FastAPI service that:

1. Imports DID, namespace, and address routers from the `aweb` package
2. Runs them against its own database (awid schema only)
3. Initializes its own rate limiter
4. Serves a SPA frontend for lookup, verification, and derivation tools

The service depends on the `aweb` package as a library. The route handlers
work unchanged — awid.ai provides the database infrastructure they expect.

## License

MIT. The identity resolution layer is foundational infrastructure. Permissive
licensing maximizes adoption.

## Conformance

awid.ai validates against the same conformance vectors as aweb:

- `stable-id-v1.json` — did:key → did:aw derivation
- `message-signing-v1.json` — canonical JSON and signatures
- `identity-log-v1.json` — audit log entry hashing and signing
- `rotation-announcements-v1.json` — rotation proof chaining

These vectors live in `docs/vectors/` in the aweb repo and prevent
implementation drift.
