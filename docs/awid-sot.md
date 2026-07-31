# awid — Source of Truth

Status: **canonical normative contract for shipped AWID identity, certificate,
and trust behavior**.

This is the canonical contract for **awid**, the public identity registry for
DIDs, namespaces, addresses, teams, and certificate issuance records.

> **Mechanical inventory contract:** the current application-table inventory
> below is checked against the complete ordered component migration chain.
> Endpoint blocks in this document are selected normative protocol surfaces,
> not an exhaustive OpenAPI
> listing; live route source/OpenAPI remains the mechanical endpoint inventory.
> This distinction does not weaken the normative identity, certificate,
> signature, revocation, or authority rules in this contract.

aweb (the coordination server that depends on awid) is described in
[`aweb-sot.md`](aweb-sot.md). The canonical product vocabulary and invariants
for namespaces, addresses, local/global identities, teams, member names, and the
three verbs live in [`identity.md`](identity.md). The supporting SOT for the
shipped route-level global/local messaging contract and legacy reachability
cleanup path is [`global-local-identity-routing.md`](global-local-identity-routing.md).
Hosted deployment details live with the hosted deployment codebase, not in this
SOT.

---

## Principles

1. **awid is a public identity registry.** It stores public data:
   DIDs, namespaces, addresses, team public keys, certificate records.
   It never holds private keys or signs on behalf of anyone.
2. **Teams are named groups within namespaces.** A team has a name,
   display name, and public key. awid stores these and the certificate
   issuance log.
3. **Certificates are signed externally and self-contained.** The team
   controller (CLI for BYOD, hosted deployment for managed namespaces)
   signs certificates. The agent carries the cert and presents it to any
   service that needs to verify team membership. awid optionally publishes
   the cert blob for cross-machine fetch and recovery, but membership
   proof comes from the presented cert + signature against the team's
   stored public key + non-revocation — NOT from row existence in awid's
   `team_certificates` table.
4. **Revocation is registry state.** Revoking a certificate sets
   `revoked_at` on the certificate record. Services check revocation as part of
   certificate verification. Public address resolution does not use a team
   certificate and does not infer delivery authorization from membership.
   Active membership is not determined by an awid member row; it is determined
   by a valid presented certificate that has not been revoked.
5. **Identity and address are separate facts, separately authorized.**
   `register_did` binds `did_aw ↔ did_key` and is authorized by the
   identity holder alone. Delivery routing for first contact is not an
   identity-level property: it comes from a concrete address route
   (`domain/name`) authorized by the namespace/address route authority.
   Binding a `did_aw` to a `(domain, name)` address is a second operation
   authorized by the namespace controller. A `did_aw` must already be
   registered before any address can be bound to it. See
   [Identity operations](#identity-operations).

---

## Authentication

awid write operations are authenticated by an Ed25519 signature over a
**canonical JSON envelope of explicit structured fields** rather than over
the request body bytes. Each operation has its own envelope shape.

Every signed write includes `operation` and `timestamp` plus the fields needed
to bind that operation. Namespace/team/address controller operations include
`domain`; DID registration and rotation instead sign the canonical identity-log
entry keyed by `did_aw`. A controller operation's timestamp is ISO 8601 UTC and
is enforced to ±300 seconds of server clock.

The operation discriminator prevents a signature for one operation from being
reused as another operation. The timestamp bounds replay exposure but does not
make an envelope nonce-based or replay-proof: an identical request can be
replayed within the accepted window. Idempotent/conflict behavior at each write
path determines whether such a retry changes state.

The signing key is the operation's authority: a parent, namespace, or team
controller for controller-scoped writes, and the identity's current signing key
for identity-scoped writes. The request carries:

```
Authorization: DIDKey <did:key:z6Mk...> <base64-signature>
```

Three controller keys exist, each with its own scope:

- **Parent controller key** (`*.aweb.ai`): managed by the hosted deployment, signs namespace
  registrations under managed domains
- **Namespace controller key**: signs namespace operations and team
  creation under a specific namespace; held by the namespace owner (BYOD)
  or by the hosted deployment (managed)
- **Team controller key**: signs team-scoped operations including
  certificate issuance, certificate revocation, and team visibility toggle;
  held by the team controller (BYOD) or by the hosted deployment (managed).
  The namespace controller authorizes replacement of a team's public key.

This is the **awid pattern**, distinct from the legacy aweb compact pattern
(`{team_id, timestamp, body_sha256}`), the request-bound aweb team-auth
envelope (`docs/team-auth-envelope-v2.md`), and the hosted deployment pattern
(`{body_sha256, method, path, timestamp}`). The patterns are not
interchangeable; see the per-endpoint signed payload examples below for each
operation's exact envelope shape.

Public read endpoints (`GET /v1/namespaces/{domain}`,
`GET /v1/did/{did_aw}/key`, team metadata, revocations, etc.) are rate-limited
and do not carry signatures. Identity-private reads and certificate-blob fetch
have their separately documented authentication requirements.

---

## Namespaces

DNS-verified organizational domains. `acme.com`, `juanre.aweb.ai`.
The exact-match reserved namespace `local` is also allowed for local
development/bootstrap without DNS verification; after creation it behaves
like any other namespace.

```
POST   /v1/namespaces                  Create (controller auth)
GET    /v1/namespaces/{domain}          Read (public)
POST   /v1/namespaces/{domain}/rotate   Rotate controller key
DELETE /v1/namespaces/{domain}          Delete (controller auth)
```

## Addresses

Identity handles within namespaces. `acme.com/alice`.

```
POST   /v1/namespaces/{domain}/addresses          Create (controller auth)
GET    /v1/namespaces/{domain}/addresses           List (public, paginated)
GET    /v1/namespaces/{domain}/addresses/{name}    Read global address handle (public resolver)
PUT    /v1/namespaces/{domain}/addresses/{name}    Compatibility no-op for legacy metadata fields (controller auth)
DELETE /v1/namespaces/{domain}/addresses/{name}    Delete (controller auth)
```

**Creation precondition.** `POST /v1/namespaces/{domain}/addresses`
requires that the target `did_aw` is already registered at awid
(see [Identity operations](#identity-operations)). If
`did_aw_mappings` has no row for the given `did_aw`, awid returns
`409 { "detail": "did_aw must be registered before address
assignment" }`. The envelope carries `current_did_key` as an
expectation check; awid rejects the request if this value does not
match the current key on record. The key is NOT stored on the
address row — it is resolved at read time via JOIN on
`did_aw_mappings`, so rotation is a single update without a cascade.
This is Principle 5 enforced at the write path.

**Authorization.** The namespace controller is the sole authority
for addresses in its namespace. The identity holder's consent to hold
the address is out-of-band: for a BYOD self-namespace the controller
and identity holder are the same party; for a managed namespace the
consent is conveyed by the API-key exchange with the hosted operator
(a separate contract, not an awid concern); for cross-namespace
membership, the identity holder may refuse inbound messaging at the
transport layer if they disagree with the claim.

**Idempotency.** `POST /v1/namespaces/{domain}/addresses` is
idempotent on exact match. If a row with the same `(domain, name)`
already exists AND its `did_aw` equals the request `did_aw` AND its
(JOIN-resolved) `current_did_key` equals the request `current_did_key`,
awid returns `200` with the existing record — the caller need not
distinguish "created just now" from "re-registered by a retry." Any
of those three values differing returns `409` (real conflict; the
name is claimed by a different identity, or the key is stale). This
mirrors `register_did`'s same-key idempotency and is the mechanism
by which a caller can safely retry after a failure whose outcome is
ambiguous (e.g., cloud transaction commit failure after awid already
accepted the address).

**Removed reachability columns and request compatibility.** Ordered migration
`003_drop_address_reachability.sql` refuses to run while an active address has
non-neutral legacy state, then drops `public_addresses.reachability` and
`visible_to_team_id`. Those columns are absent from the current schema and from
address responses. The create/update request models still accept the two old
field names so old clients do not fail parsing, but the service ignores them;
the `PUT` path performs no metadata mutation and returns the current public
address resolution.

`GET /v1/namespaces/{domain}/addresses/{name}` is public. Legacy clients may
still send old authorization/timestamp/team-certificate headers, but the read
path does not inspect them or grant elevated visibility. Team certificates do
not grant special address-discovery authority. Abuse controls belong at rate
limiting, recipient-side delivery policy, and spam/blocklist layers after
identity/route resolution.

## Identity operations

Identity at awid is a `did_aw ↔ did_key` binding. It carries no address,
handle, or delivery route. An identity can exist without ever being bound
to an address, and the same `did_aw` can subsequently hold zero, one, or
many addresses across one or many namespaces. Each address is its own
first-contact route and may inherit route origin from its namespace
`default_delivery_origin`.

```
POST   /v1/did                         register_did (identity auth)
POST   /v1/did/{did_aw}/rotate         rotate_key (identity auth)
GET    /v1/did/{did_aw}/key            Resolve current key (public)
GET    /v1/did/{did_aw}/full           Full info (identity auth)
GET    /v1/did/{did_aw}/log            Audit log (public)
GET    /v1/did/{did_aw}/addresses      List addresses (public)
```

Address binding is not an identity operation. It is an address
operation, authorized by the namespace controller, and lives under
`POST /v1/namespaces/{domain}/addresses` (see [Addresses](#addresses)).

### Why identity and address are split

Identity is "what key speaks for `did_aw`". Address is "which
`(domain, name)` handle `did_aw` holds". These are semantically
independent claims with different authority:

- The identity holder alone authorizes changes to their own key
  binding. No namespace controller can rotate someone else's identity
  key.
- The namespace controller alone authorizes who gets which address
  under their namespace. A `did_aw` cannot insert itself into a
  namespace it was not given.

Bundling the two into a single signed operation (as earlier versions
did) forced a cycle for managed addresses: the identity holder had to
sign over an address they did not yet own, and the namespace controller
had to accept an identity claim they had no authority over. The split
makes each operation authorizable by the one party that legitimately
holds authority, and makes the "identity must exist before address"
invariant structural rather than a runtime check.

### Canonical entry payload (shared by all identity ops)

Every identity operation — `register_did`, `rotate_key`, and any
future op — writes one log entry whose shape is identical. The
signed object is the **canonical entry payload** below; its bytes
are hashed into `entry_hash` and signed into `proof`.

```json
{
  "authorized_by":    "did:key:z6Mk...",
  "did_aw":           "did:aw:...",
  "new_did_key":      "did:key:z6Mk...",
  "operation":        "<register_did | rotate_key | ...>",
  "prev_entry_hash":  "<hex | null>",
  "previous_did_key": "<did:key | null>",
  "seq":              1,
  "state_hash":       "<hex>",
  "timestamp":        "ISO 8601 UTC"
}
```

Rules:

- Keys are sorted alphabetically. No whitespace. UTF-8.
- `entry_hash = sha256(canonical_entry_payload_bytes)`. Stored in
  `did_aw_log`; used as `prev_entry_hash` in the next entry.
- `proof = Ed25519.sign(authorized_by_private, canonical_entry_payload_bytes)`.
- `state_hash = sha256(canonical_json({"current_did_key": new_did_key, "did_aw": did_aw}))`.
  Identity-only; no address, server, or handle input.
- `state_hash` is **inside** the signed payload. This pins the
  canonicalization (every implementation must agree on the signer's
  bytes) and makes each entry a standalone self-proving artifact.
- The uniform shape is deliberate: a log entry is a state transition,
  and every transition has both a "from" (`previous_did_key`) and a
  "to" (`new_did_key`). `register_did` is the case where "from" is
  null; future ops (custody transfer, revoke, reinstate) slot into
  the same shape without adding parsers.

### `register_did`

Binds `did_aw ↔ did_key`. Idempotent for the same `(did_aw, new_did_key)`
pair; a different `new_did_key` for an existing `did_aw` is rejected
(clients must call `rotate_key`).

Entry-field values specific to this op:

- `operation`: `"register_did"`
- `new_did_key`: the key being bound
- `previous_did_key`: `null`
- `prev_entry_hash`: `null`
- `seq`: `1`
- `authorized_by`: equals `new_did_key` — the identity holder
  authorizes its own registration
- `proof` is signed by the private half of `new_did_key`

```
POST /v1/did
     Body: { <canonical entry payload fields>, "proof": "<base64>" }
     Response: { "registered": true, "did_aw": "...",
                 "current_did_key": "..." }
```

The state derivable from this entry is
`{"current_did_key": new_did_key, "did_aw": did_aw}`. No `server`,
`address`, `handle`, or delivery origin appears in the DID log entry;
addresses and address-route delivery origins are separate concerns maintained
under namespace/address route authority.

### `rotate_key`

Replaces the `did_key` for an existing `did_aw`. Same canonical
entry payload as above, with the rotate-specific field values:

- `operation`: `"rotate_key"`
- `new_did_key`: the replacement key
- `previous_did_key`: the retiring key
- `prev_entry_hash`: `entry_hash` of the previous log entry
- `seq`: previous entry's `seq + 1`
- `authorized_by`: equals `previous_did_key` — the retiring key
  signs its own replacement
- `proof` is signed by the private half of `previous_did_key`

After the rotation is appended to the log, `new_did_key` becomes the
`current_did_key` in `did_aw_mappings`.

Rotation is a single-row update of `did_aw_mappings.current_did_key`
plus one append to `did_aw_log`. There is no cascade to address rows:
`public_addresses` does not store the current key — address reads
resolve it via JOIN on `did_aw_mappings`. Any number of addresses
can be bound to a `did_aw` without affecting rotation cost or
introducing multi-row consistency concerns.

### Address bindings

Address bindings are listed at `GET /v1/did/{did_aw}/addresses`. They
are not created by identity operations. To bind an address, the
namespace controller calls `POST /v1/namespaces/{domain}/addresses`
(see [Addresses](#addresses)).

Invariant: awid returns `409 { "detail": "did_aw must be registered
before address assignment" }` on address creation if the referenced
`did_aw` has no row in `did_aw_mappings`. This is the mechanical
enforcement of Principle 5.

### Read endpoints

- `GET /v1/did/{did_aw}/key` — current `did_key`. Public. Used by aweb
  and other services for message-signature verification. It is not a
  delivery route lookup.
- `GET /v1/did/{did_aw}/full` — full identity record. Identity auth (the
  DID holder).
- `GET /v1/did/{did_aw}/log` — append-only audit log of `register_did`
  and `rotate_key` entries. Public. The log never contains address
  entries; address history lives with each address record.
- `GET /v1/did/{did_aw}/addresses` — list of addresses currently
  bound to this `did_aw`. Public. Reflects the `public_addresses`
  table, not `did_aw_mappings`.

---

## Teams

A team is a named group within a namespace. It has a name, display name,
public key, and visibility (`public` or `private`). The `team_certificates`
log records certificates published to AWID; `active_only=true` lists published
rows where `revoked_at IS NULL`. Row existence is not the membership
authorization oracle: a verifier uses the presented controller-signed
certificate plus non-revocation. See the [ordered schema
contract](#awid-database-schema) for storage authority.

### Endpoints

```
POST   /v1/namespaces/{domain}/teams
       Create team.
       Auth: namespace controller DIDKey signature.
       Body: { "name": "backend",
               "display_name": "Backend Team",
               "team_did_key": "did:key:z6Mk...",
               "visibility": "private" | "public" }
       The caller generates the team keypair and provides the public
       key. awid never sees the private key.
       Response: { "team_id": "backend:acme.com", "domain": "acme.com",
                   "name": "backend", "display_name": "Backend Team",
                   "team_did_key": "did:key:z6Mk...",
                   "visibility": "private",
                   "created_at": "..." }

GET    /v1/namespaces/{domain}/teams
       List teams in namespace.
       Auth: none (public).
       Response: { "teams": [{ "name": "backend",
                   "display_name": "Backend Team",
                   "team_did_key": "did:key:z6Mk...",
                   "visibility": "private", ... }] }

GET    /v1/namespaces/{domain}/teams/{name}
       Get team details.
       Auth: none (public). Services call this to get the team
       public key and visibility metadata for certificate verification
       and dashboard auth.
       Response: { "team_id": "backend:acme.com", "domain": "acme.com",
                   "name": "backend", "display_name": "Backend Team",
                   "team_did_key": "did:key:z6Mk...",
                   "visibility": "private" | "public",
                   "created_at": "..." }

DELETE /v1/namespaces/{domain}/teams/{name}
       Delete team.
       Auth: namespace controller DIDKey signature.

POST   /v1/namespaces/{domain}/teams/{name}/rotate
       Rotate team public key.
       Auth: namespace controller DIDKey signature.
       Body: { "new_team_did_key": "did:key:z6Mk..." }
       Note: invalidates ALL existing certificates (they were
       signed by the old key). Members need new certificates.

POST   /v1/namespaces/{domain}/teams/{name}/visibility
       Set team visibility.
       Auth: team controller DIDKey signature.
       Body: { "visibility": "private" | "public" }
       Signed payload:
       { "domain": "...",
         "operation": "set_team_visibility",
         "team_name": "...",
         "visibility": "...",
         "timestamp": "..." }
       Response: full team object including updated visibility.

POST   /v1/namespaces/{domain}/teams/{name}/certificates
       Register a certificate.
       Auth: team controller DIDKey signature.
       Body: { "certificate_id": "uuid",
               "member_did_key": "did:key:z6Mk...",
               "member_did_aw": "did:aw:...",
               "member_address": "acme.com/alice",
               "alias": "alice",
               "identity_scope": "global",
               "certificate": "<optional base64 certificate JSON>" }
       The canonical product term for the per-team routing key is member name;
       the current wire/schema field is still "alias" until the scheduled
       compatibility rename. Compatibility clients may send "lifetime"
       (legacy global/local storage); awid normalizes it to identity_scope
       before storage and never emits it in normal certificate responses.
       The certificate is signed externally by whoever holds the
       team controller private key (CLI for BYOD, hosted deployment for
       managed). awid records the issuance but does not sign.
       member_address is the address selected for this specific team
       membership. A did:aw may have many awid addresses; the team
       certificate chooses which one is used when acting as this team
       member. If member_address is present, awid validates that it
       resolves to member_did_aw before recording the certificate.
       Response: { "registered": true, "certificate_id": "uuid" }

GET    /v1/namespaces/{domain}/teams/{name}/certificates
       List issued certificates (active and revoked).
       Auth: none (public).
       Query params: active_only (boolean), since (timestamp)
       Response: { "certificates": [{
                   "team_id": "backend:acme.com",
                   "certificate_id": "uuid",
                   "member_did_key": "did:key:z6Mk...",
                   "member_did_aw": "did:aw:...",
                   "member_address": "acme.com/alice",
                   "alias": "alice",
                   "identity_scope": "global",
                   "issued_at": "...",
                   "revoked_at": null }] }
       With active_only=true: only rows where revoked_at IS NULL.
       This is how the dashboard lists team members.

GET    /v1/namespaces/{domain}/teams/{name}/members/{alias}
       Resolve an active team-member reference. The path segment is the
       member name; it is called alias in the current wire path for
       compatibility.
       Auth: none (public).
       Response: { "team_id": "backend:acme.com",
                   "certificate_id": "uuid",
                   "member_did_key": "did:key:z6Mk...",
                   "member_did_aw": "did:aw:...",
                   "member_address": "acme.com/alice",
                   "alias": "alice",
                   "identity_scope": "global",
                   "issued_at": "..." }
       This is the canonical `(team_id, member name)` lookup layer; the wire
       field remains `alias` during the compatibility window.

POST   /v1/namespaces/{domain}/teams/{name}/certificates/revoke
       Revoke a certificate.
       Auth: team controller DIDKey signature.
       Body: { "certificate_id": "uuid" }
       Response: { "revoked": true }
       Sets revoked_at on the certificate row.

GET    /v1/namespaces/{domain}/teams/{name}/revocations
       List revoked certificates only.
       Auth: none (public). Services cache this.
       Query params: since (timestamp, optional — for incremental sync)
       Response: { "revocations": [{ "certificate_id": "uuid",
                   "revoked_at": "..." }] }
       This is what services cache to reject removed members.
```

---

## Certificates

### What they are

A certificate is a JSON document signed by the team controller's
private key. It proves that a specific did:key is authorized as a
member of a specific team. The agent carries it and presents it to
any service.

`member_address` is per team membership, not per identity. A global
`did:aw` can hold multiple addresses at awid; each team certificate
selects at most one address for that `(team_id, member)` relationship.
Services use the address in the active team certificate as the sender's
routable address for that team. They must not infer a canonical address
by listing all addresses for a `did:aw`.

### Structure

```json
{
  "version": 1,
  "certificate_id": "uuid",
  "team_id": "backend:acme.com",
  "team_did_key": "did:key:z6Mk...(team public key)",
  "member_did_key": "did:key:z6Mk...(agent's key)",
  "member_did_aw": "did:aw:...(agent's stable ID, empty for local)",
  "member_address": "acme.com/alice (empty for local)",
  "alias": "alice",
  "identity_scope": "global",
  "issued_at": "2026-04-06T...",
  "signature": "base64...(Ed25519 by team private key)"
}
```

No `expires_at` field. The certificate is valid until revoked.

### Signing

```
signature = Ed25519.sign(
    team_private_key,
    canonical_json(certificate_without_signature)
)
```

Canonical JSON: sorted keys, no whitespace, UTF-8.

### Who signs certificates

- **BYOD teams**: the team controller (human or agent) holds the
  team private key locally. They sign certificates via
  `aw id team add-member` and register them at awid.
- **Managed teams (*.aweb.ai)**: the hosted deployment holds the team controller
  private key (encrypted). It signs certificates and registers
  them at awid. awid never sees the private key.

AWID records the certificate fact. It does not create or mutate aweb runtime
rows. The shipped OSS aweb projection path is a certified member's
`POST /v1/connect`; any operator-specific bulk import or dashboard adapter is
external to both the AWID registry and OSS aweb server contracts.

### Issuance flow

For cross-machine BYOIT membership, the controller machine owns the
team private key and the joining machine owns the member identity key.
Those keys must not move between machines.

1. Joining agent identifies its `did:key` and optional `did:aw` address
   (`aw id team request` can print the controller-side command).
2. Team controller approves the member with `aw id team add-member`.
3. Team controller signs the certificate for the member's did:key.
4. Team controller registers certificate metadata and the full signed
   public certificate blob at awid
   (`POST /v1/namespaces/{domain}/teams/{name}/certificates`)
5. Joining agent fetches the blob with identity auth
   (`aw id team fetch-cert --namespace <domain> --team <team> --cert-id <id>`).
6. CLI verifies that the fetched certificate matches the local signing key
   and requested team, then stores it under `.aw/team-certs/`.

For a managed team, the same certificate record may be signed by an external
hosted operator that holds the team controller key. The raw
`aw id team add-member` command remains a local-controller command and cannot
operate without that key. Any hosted dashboard operation that signs a
certificate or bulk-projects members is the operator's adapter, not an AWID or
OSS aweb endpoint.

A BYOIDT team may be created and populated entirely in AWID before using aweb.
To enter shipped OSS aweb runtime state, a member presents its valid
certificate to `POST /v1/connect`; aweb verifies public AWID facts and does not
require or store the team controller private key. An optional external
import/sync adapter may orchestrate equivalent public facts, but it remains
outside this canonical OSS server/registry contract.

Registration is atomic from the registry contract's point of view: awid
validates the signed blob against the team record and request metadata, then
stores metadata and blob in one certificate record. A registry must not create
a metadata-only record after accepting a blob-backed registration request.

The certificate blob is not a secret. It contains public identity and
membership claims plus the controller signature, and agents already send it
to aweb services on authenticated requests. awid stores the blob so a
member can retrieve its own certificate without access to the controller
private key or the controller machine's local invite state. awid never stores
or derives the team controller private key.

Pre-blob metadata-only certificate records are not fetchable. If a member
requests a certificate record that exists but has no stored blob, awid returns
HTTP 409 with an explicit not-fetchable/reissue message. The CLI must surface
that as an instruction to have the controller reissue/register a blob-backed
certificate; it must not attempt to reconstruct a certificate locally or claim
that the install succeeded.

Fetch responses are JSON envelopes, not raw files:

```json
{
  "team_id": "backend:acme.com",
  "certificate_id": "uuid",
  "member_did_key": "did:key:z6Mk...",
  "member_did_aw": "did:aw:...",
  "member_address": "acme.com/alice",
  "alias": "alice",
  "identity_scope": "global",
  "issued_at": "2026-04-06T...",
  "revoked_at": null,
  "certificate": "<base64-encoded certificate JSON>"
}
```

The `certificate` field is base64 of the exact UTF-8 team certificate JSON
document that the CLI stores and sends as `X-AWID-Team-Certificate`; it is not
PEM and is not an inline JSON object.

Compatibility note: pre-migration certificate blobs and legacy registration
requests may still carry `lifetime`. Migration 004 removed `lifetime` from the
current database schema; the registration boundary normalizes legacy input to
`identity_scope`. The canonical contract for new docs, examples, and product
language is `identity_scope=global|local`; services that accept the old field
must normalize it at the boundary and must not teach it as product authority.

`aw id team fetch-cert` is refuse-overwrite by default. If a local
certificate already exists for the target team with a different
`certificate_id`, the CLI must stop and require `--force` before replacing it.
Re-running fetch for the same certificate id is idempotent.

### Reissuance (rare)

A new certificate is needed only when:
- Agent rotates their key (`aw id rotate-key`) — old did:key in
  certificate no longer matches
- Team key is rotated — old certificates have signatures from the
  old key

awid certificate records are append-only for reissuance. A replacement
certificate creates a new `certificate_id` and stores a new blob; existing
records remain available unless revoked. Controllers should revoke superseded
certificates when they should no longer authenticate. Fetching a revoked
certificate returns a revoked error rather than the blob.

Both are administrative events, not routine operations.

### Verification by a service

1. Decode certificate JSON.
2. Verify Ed25519 signature against `team_did_key` (the team's
   public key, cached from awid).
3. Verify `member_did_key` matches the `did:key` in the request's
   `Authorization` header.
4. Check `certificate_id` against cached revocation list.
5. If all pass, the request is authorized for the team.

Steps 1-3 are local crypto, no network. Step 4 is a cache lookup
(revocation list fetched periodically from awid).

### Revocation

When the team controller removes a member:
1. `aw id team remove-member` calls awid:
   `POST /v1/namespaces/{domain}/teams/{name}/certificates/revoke`
   with the `certificate_id`.
2. awid sets `revoked_at` on the `team_certificates` row.
3. The revoked certificate is rejected by services on the next request
   after they refresh their cached revocation list. Cache TTL is a
   property of each consumer, not of awid; aweb's TTL is documented in
   the aweb SoT under "Caching from awid".

---

## Cross-namespace team membership

A team in one namespace can include members from other namespaces. The
membership certificate is signed by the team controller of the namespace
that owns the team, and the certificate's `member_address` field carries
the cross-namespace address.

Example: a team in `acme.com` namespace adds `partner.com/bob` as a member.
The certificate is signed by the `backend:acme.com` team controller. The
verifying service sees that bob (whose home namespace is `partner.com`) is
a member of `backend:acme.com`. No special protocol support is needed —
the certificate format already accommodates this because `member_address`
is just a string and is not constrained to match the team's namespace.

Authorization model: the team controller is the authority for membership in
its team. It signs the certificate that says `partner.com/bob` is a member of
`backend:acme.com`; it does not control the external address. Namespace
authority is needed only to claim or control an address in that namespace. In
the example, the `partner.com` namespace has already authorized the address
binding that makes `partner.com/bob` resolve to Bob's `did:aw`. AWID validates
that a non-empty `member_address` on a registered certificate resolves to the
certificate's `member_did_aw`; it does not authorize the membership itself.
Services may also resolve the address when they need fresh address-route or
current-key data.

---

## awid database schema

AWID applies the files in `awid/src/awid_service/migrations/` in filename order
to the `awid` schema by default, with pgdbm module name `awid-service` and
migration table `schema_migrations`. Applied files are immutable because pgdbm
records their checksums. Any schema change after an applied migration is a new
forward migration; in particular, `001_registry.sql` is not edited to retrofit
later state.

Current ordered effects are:

1. `001_registry.sql` creates the base DID log, namespaces, addresses,
   replacement announcements, teams, and certificate records.
2. `002_namespace_delivery_origin.sql` adds namespace-level address-route
   delivery origin.
3. `003_drop_address_reachability.sql` guards and then drops the two legacy
   address reachability columns.
4. `004_team_certificate_identity_scope.sql` migrates `lifetime` to canonical
   `identity_scope` and drops `lifetime` from storage.
5. `005_identity_encryption_keys.sql` adds identity-signed **public** encryption
   key assertions; it does not store private encryption keys.
6. `006_identity_encryption_key_custody.sql` adds the assertion custody signal.
7. `007_a2a_publications.sql` adds digest-bound A2A delegation/publication
   records.

The following inventory is exhaustive for current **AWID application tables
declared by** that ordered component chain. It intentionally excludes pgdbm's
manager-created `schema_migrations` metadata table.
`scripts/check_sot_source_inventories.py` derives it from the SQL, applies
`CREATE`/`DROP` events, preserves first-creation order, and fails when source
and this list diverge. Current column, constraint, and index authority is the
full ordered SQL, not a copied `001` snapshot.

<!-- BEGIN SOURCE INVENTORY: awid-tables -->
- `did_aw_mappings`
- `did_aw_log`
- `dns_namespaces`
- `public_addresses`
- `replacement_announcements`
- `teams`
- `team_certificates`
- `identity_encryption_keys`
- `a2a_bridge_delegations`
- `a2a_route_publications`
<!-- END SOURCE INVENTORY: awid-tables -->

---

## Configuration

### Environment variables

```bash
# Required
DATABASE_URL=postgresql://awid:password@localhost:5432/awid

# Server
AWID_PORT=8001
AWID_LOG_JSON=true
```

awid has no encryption keys, no custody keys, no signing keys.
It is a public registry. All private key operations happen at
the CLI (BYOD) or the hosted deployment (managed namespaces).

---

## Responsibilities

**Does:**
- Store team name, display name, and public key
- Serve team public keys so verifiers can validate presented certs
- Record certificate revocation events (`revoked_at` on the cert row)
- Serve revocation lists for services to cache
- Optionally publish cert blobs (per aala) for cross-machine fetch and
  recovery — not load-bearing for authorization
- Serve cert listings for optional dashboard / audit / discovery

**Does not:**
- Hold private keys (no escrow, no custody keys)
- Sign certificates (signing is external)
- Sign on behalf of agents (custody is a hosted deployment concern)
- Use `team_certificates` row existence as the authorization oracle — auth
  is presentation-based: cert signature against team public key + non-
  revocation. A correctly signed, non-revoked cert authorizes its holder
  whether or not the cert was published to awid
- Track certificate expiry (certificates are long-lived)
- Coordinate agents (aweb does this)
- Manage billing (the hosted deployment does this)
- Manage human accounts (the hosted deployment does this)
