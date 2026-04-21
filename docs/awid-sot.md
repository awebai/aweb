# awid — Source of Truth

This is the canonical contract for **awid**: the public identity registry
that holds DIDs, namespaces, addresses, teams, and certificate issuance
records. It is the implementation spec for the awid.ai service.

aweb (the coordination server that depends on awid) is described in
[`aweb-sot.md`](aweb-sot.md). Hosted deployment details live with the
hosted deployment codebase, not in this SOT.

---

## Principles

1. **awid is a public identity registry.** It stores public data:
   DIDs, namespaces, addresses, team public keys, certificate records.
   It never holds private keys or signs on behalf of anyone.
2. **Teams are named groups within namespaces.** A team has a name,
   display name, and public key. awid stores these and the certificate
   issuance log.
3. **Certificates are signed externally.** The team controller (CLI
   for BYOD, hosted deployment for managed namespaces) signs certificates
   and registers them at awid. awid records the issuance but does not
   perform the signing.
4. **Revocation is a column update.** Revoking a certificate sets
   `revoked_at` on the certificate record. Services cache the revoked
   entries.
5. **Identity and address are separate facts, separately authorized.**
   `register_did` binds `did_aw ↔ did_key` and is authorized by the
   identity holder alone. Binding that `did_aw` to a `(domain, name)`
   address is a second operation authorized by the namespace controller.
   A `did_aw` must already be registered before any address can be bound
   to it. See [Identity operations](#identity-operations).

---

## Authentication

awid write operations are authenticated by an Ed25519 signature over a
**canonical JSON envelope of explicit structured fields** rather than over
the request body bytes. Each operation has its own envelope shape.

The envelope always includes:

- `domain` — the namespace the operation applies to
- `operation` — a string that locks the signature to a specific operation,
  preventing cross-operation replay (e.g. `set_team_visibility`,
  `register_address`, `revoke_certificate`)
- `timestamp` — ISO 8601 UTC, enforced to ±300 seconds of server clock
- additional operation-specific fields (e.g. `team_name`, `visibility`,
  `certificate_id`, `address_name`)

The signature is `Ed25519.sign(controller_private_key, canonical_json(envelope))`.
The request also carries:

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
  certificate issuance, certificate revocation, team visibility toggle,
  and team key rotation; held by the team controller (BYOD) or by
  the hosted deployment (managed)

This is the **awid pattern**, distinct from the aweb pattern
(`{team_id, timestamp, body_sha256}`) and the hosted deployment pattern
(`{body_sha256, method, path, timestamp}`). The three patterns are not
interchangeable; see the per-endpoint signed payload examples below for
each operation's exact envelope shape.

Read endpoints (`GET /v1/namespaces/{domain}`, `GET /v1/did/{did_aw}/key`,
team metadata, revocations, etc.) are public and rate-limited. They do
not carry signatures.

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
GET    /v1/namespaces/{domain}/addresses/{name}    Read (public)
PUT    /v1/namespaces/{domain}/addresses/{name}    Update reachability
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

**Reachability enforcement:**
- `public` — any caller, anonymous or authenticated
- `nobody` — owner only; the caller's `did:aw` must match the address `did_aw`
- `org_only` — owner, or any caller holding an active persistent team certificate for a team in the same namespace domain
- `team_members_only` — owner, or any caller holding an active persistent team certificate for the specific team in `visible_to_team_id`

Ephemeral team certificates (`lifetime='ephemeral'`) do not satisfy
`org_only` or `team_members_only` checks. Anonymous callers see only
public addresses; non-public addresses return `404`, not `403`, to avoid
leaking existence.

## Identity operations

Identity at awid is a pure `did_aw ↔ did_key` binding. It carries no
address, no server, no handle. An identity can exist without ever being
bound to an address, and the same `did_aw` can subsequently hold zero,
one, or many addresses across one or many namespaces.

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
`address`, or `handle` appears anywhere in the entry or its state;
addresses are a separate concern maintained in `public_addresses`.

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

- `GET /v1/did/{did_aw}/key` — current `did_key`. Public. Used by
  aweb and other services for message-signature verification.
- `GET /v1/did/{did_aw}/full` — full identity record including
  metadata. Identity auth (the DID holder).
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
log records every certificate issued for the team; active members are rows
where `revoked_at IS NULL`. See [awid database schema](#awid-database-schema)
for the full DDL.

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
               "lifetime": "persistent" }
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
                   "lifetime": "persistent",
                   "issued_at": "...",
                   "revoked_at": null }] }
       With active_only=true: only rows where revoked_at IS NULL.
       This is how the dashboard lists team members.

GET    /v1/namespaces/{domain}/teams/{name}/members/{alias}
       Resolve an active team-member reference.
       Auth: none (public).
       Response: { "team_id": "backend:acme.com",
                   "certificate_id": "uuid",
                   "member_did_key": "did:key:z6Mk...",
                   "member_did_aw": "did:aw:...",
                   "member_address": "acme.com/alice",
                   "alias": "alice",
                   "lifetime": "persistent",
                   "issued_at": "..." }
       This is the canonical `(team_id, alias)` lookup layer.

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

`member_address` is per team membership, not per identity. A persistent
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
  "member_did_aw": "did:aw:...(agent's stable ID, empty for ephemeral)",
  "member_address": "acme.com/alice (empty for ephemeral)",
  "alias": "alice",
  "lifetime": "persistent",
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

### Issuance flow

1. Team controller invites agent (`aw id team invite`)
2. Agent accepts (`aw id team accept-invite <token>`)
3. Team controller signs certificate for the agent's did:key
4. Team controller registers certificate at awid
   (`POST /v1/namespaces/{domain}/teams/{name}/certificates`)
5. Certificate delivered to agent, stored under `.aw/team-certs/`

### Reissuance (rare)

A new certificate is needed only when:
- Agent rotates their key (`aw id rotate-key`) — old did:key in
  certificate no longer matches
- Team key is rotated — old certificates have signatures from the
  old key

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

Authorization model: the namespace controller of the team-owning namespace
(`acme.com` in the example) is the sole authority for adding cross-namespace
members. The home namespace of the external member (`partner.com`) does
not need to authorize anything — the team controller is making a claim
about who is in their team, not about who controls the external address.
awid enforces that a non-empty `member_address` on a registered
certificate resolves to the certificate's `member_did_aw`; services may
also resolve the address when they need fresh reachability or current-key
data.

---

## awid database schema

```sql
CREATE TABLE did_aw_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did_aw          TEXT UNIQUE NOT NULL,
    current_did_key TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Identity rows carry no address, server, or handle. Address records
-- live in public_addresses; the (did_aw → addresses) projection is
-- served by GET /v1/did/{did_aw}/addresses.

CREATE TABLE did_aw_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did_aw          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    operation       TEXT NOT NULL,
    previous_did_key TEXT,
    new_did_key     TEXT NOT NULL,
    prev_entry_hash TEXT,
    entry_hash      TEXT NOT NULL,
    state_hash      TEXT NOT NULL,
    authorized_by   TEXT NOT NULL,
    signature       TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (did_aw, seq)
);

CREATE TABLE dns_namespaces (
    namespace_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT UNIQUE NOT NULL,
    controller_did  TEXT,
    scope_id        UUID,
    verification_status TEXT NOT NULL DEFAULT 'pending',
    last_verified_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE TABLE public_addresses (
    address_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
    did_aw          TEXT NOT NULL REFERENCES did_aw_mappings(did_aw),
    reachability    TEXT NOT NULL DEFAULT 'nobody'
                    CHECK (reachability IN ('nobody', 'org_only', 'team_members_only', 'public')),
    visible_to_team_id TEXT
                    CHECK (
                        (reachability = 'team_members_only' AND visible_to_team_id IS NOT NULL)
                        OR (reachability != 'team_members_only' AND visible_to_team_id IS NULL)
                    ),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (domain, name)
);

-- public_addresses does not store current_did_key. Address lookups
-- that need the key (e.g., GET /v1/namespaces/{domain}/addresses/{name})
-- JOIN on did_aw_mappings by did_aw. The FK enforces the invariant
-- that every address points to a registered DID (Principle 5).

CREATE TABLE teams (
    team_uuid       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    team_did_key    TEXT NOT NULL,
    visibility      TEXT NOT NULL DEFAULT 'private'
                    CHECK (visibility IN ('public', 'private')),
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (domain, name) WHERE deleted_at IS NULL
);

-- Soft delete on teams allows name reuse after deletion.
-- The team_certificates log records every certificate issued for a team.
-- Active members = rows where revoked_at IS NULL.
-- Services cache the revoked rows to reject removed members.
CREATE TABLE team_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_uuid       UUID NOT NULL REFERENCES teams(team_uuid),
    certificate_id  TEXT NOT NULL,
    member_did_key  TEXT NOT NULL,
    member_did_aw   TEXT,
    member_address  TEXT, -- address selected for this team membership
    alias           TEXT NOT NULL,
    lifetime        TEXT NOT NULL DEFAULT 'persistent'
                    CHECK (lifetime IN ('persistent', 'ephemeral')),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,

    UNIQUE (team_uuid, certificate_id)
);

CREATE INDEX idx_team_certificates_active
    ON team_certificates (team_uuid, member_did_key)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX idx_team_certificates_alias_active
    ON team_certificates (team_uuid, alias)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_team_certificates_revoked
    ON team_certificates (team_uuid, revoked_at) WHERE revoked_at IS NOT NULL;
```

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
- Record certificate issuance (who, when, revocation status)
- Serve team public keys for certificate verification
- Serve revocation lists for services to cache
- Serve active certificate lists for dashboard member enumeration

**Does not:**
- Hold private keys (no escrow, no custody keys)
- Sign certificates (signing is external)
- Sign on behalf of agents (custody is a hosted deployment concern)
- Store certificate content (agents hold their own)
- Track certificate expiry (certificates are long-lived)
- Coordinate agents (aweb does this)
- Manage billing (the hosted deployment does this)
- Manage human accounts (the hosted deployment does this)
