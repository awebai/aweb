# awid — Team Architecture Source of Truth

This document defines the awid.ai service after adding teams. It is
the implementation spec.

---

## Principles

1. **awid is the identity registry.** DIDs, namespaces, addresses,
   audit log. This exists today and does not change.
2. **Teams are named groups within namespaces.** A team has a public
   key. That's all awid stores about a team.
3. **Membership lives in certificates, not in awid.** The team
   controller signs certificates for members. Agents carry their
   certificates. awid has no members table.
4. **Revocation is a lightweight list.** When a member is removed,
   the team controller posts a revocation entry. Services cache the
   revocation list.

---

## What exists today (no changes)

### Namespaces

DNS-verified organizational domains. `acme.com`, `juanre.aweb.ai`.

```
POST   /v1/namespaces                  Create (controller auth)
GET    /v1/namespaces/{domain}          Read (public)
POST   /v1/namespaces/{domain}/rotate   Rotate controller key
DELETE /v1/namespaces/{domain}          Delete (controller auth)
```

### Addresses

Identity handles within namespaces. `acme.com/alice`.

```
POST   /v1/namespaces/{domain}/addresses          Create (controller auth)
GET    /v1/namespaces/{domain}/addresses           List (public, paginated)
GET    /v1/namespaces/{domain}/addresses/{name}    Read (public)
PATCH  /v1/namespaces/{domain}/addresses/{name}    Update reachability
DELETE /v1/namespaces/{domain}/addresses/{name}    Delete (controller auth)
```

### DID registry

Stable identity mappings. `did:aw` → `did:key`.

```
POST   /v1/did                         Register (identity auth)
GET    /v1/did/{did_aw}/key            Resolve current key (public)
GET    /v1/did/{did_aw}/full           Full info (identity auth)
GET    /v1/did/{did_aw}/log            Audit log (public)
POST   /v1/did/{did_aw}/rotate         Rotate key (identity auth)
GET    /v1/did/{did_aw}/addresses      List addresses (public)
```

### Custody signing

Sign payloads on behalf of custodial agents whose keys are held in
escrow.

```
POST   /v1/custody/sign               Sign payload (internal auth)
```

---

## What's added: Teams

### Data model

```sql
-- Teams. A named group within a namespace.
-- The team_did_key is the public key used to verify membership
-- certificates. The team controller holds the private key.
CREATE TABLE teams (
    team_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (domain, name)
);

-- Revocations. When a member is removed from a team, the
-- certificate_id is added here. Services cache this list
-- and reject revoked certificates.
CREATE TABLE team_revocations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(team_id),
    certificate_id  TEXT NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_id, certificate_id)
);

CREATE INDEX idx_team_revocations_team
    ON team_revocations (team_id, revoked_at);
```

No members table. Membership is proven by certificates held by agents.

### Endpoints

```
POST   /v1/namespaces/{domain}/teams
       Create team.
       Auth: namespace controller DIDKey signature.
       Body: { "name": "backend", "team_did_key": "did:key:z6Mk..." }
       Response: { "team_id": "uuid", "domain": "acme.com",
                   "name": "backend", "team_did_key": "did:key:z6Mk...",
                   "created_at": "..." }

GET    /v1/namespaces/{domain}/teams
       List teams in namespace.
       Auth: none (public).
       Response: { "teams": [{ "name": "backend",
                   "team_did_key": "did:key:z6Mk...", ... }] }

GET    /v1/namespaces/{domain}/teams/{name}
       Get team details.
       Auth: none (public). Services call this to get the team
       public key for certificate verification.
       Response: { "team_id": "uuid", "domain": "acme.com",
                   "name": "backend",
                   "team_did_key": "did:key:z6Mk...",
                   "created_at": "..." }

DELETE /v1/namespaces/{domain}/teams/{name}
       Delete team.
       Auth: namespace controller DIDKey signature.

POST   /v1/namespaces/{domain}/teams/{name}/rotate
       Rotate team key.
       Auth: namespace controller DIDKey signature.
       Body: { "new_team_did_key": "did:key:z6Mk..." }
       Note: invalidates ALL existing certificates (they were
       signed by the old key). Members need new certificates.

POST   /v1/namespaces/{domain}/teams/{name}/revocations
       Revoke a certificate.
       Auth: team controller DIDKey signature.
       Body: { "certificate_id": "uuid" }
       Response: { "revoked": true }
       Called when removing a member from the team.

GET    /v1/namespaces/{domain}/teams/{name}/revocations
       List revocations.
       Auth: none (public). Services cache this.
       Query params: since (timestamp, optional — for incremental sync)
       Response: { "revocations": [{ "certificate_id": "uuid",
                   "revoked_at": "..." }] }
```

### What awid does NOT store about teams

- No members list. The certificate is the membership proof.
- No certificate copies. The agent holds its certificate.
- No certificate expiry tracking. Certificates are long-lived.
- No renewal infrastructure. Certificates are reissued only on key
  rotation.

---

## Certificates

### What they are

A certificate is a JSON document signed by the team controller's
private key. It proves that a specific did:key is authorized as a
member of a specific team. The agent carries it and presents it to
any service.

### Structure

```json
{
  "version": 1,
  "certificate_id": "uuid",
  "team": "acme.com/backend",
  "team_did_key": "did:key:z6Mk...(team public key)",
  "member_did_key": "did:key:z6Mk...(agent's key)",
  "member_did_aw": "did:aw:...(agent's stable ID, empty for ephemeral)",
  "member_address": "acme.com/alice (empty for ephemeral)",
  "alias": "alice",
  "lifetime": "permanent",
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

- **Self-custodial team controller**: the human or agent who created
  the team holds the team private key locally. They sign certificates
  via `aw id team add-member` or `aw id team accept-invite`.
- **Managed team controller**: for managed namespaces (*.aweb.ai),
  awid holds the team controller key in escrow. aweb-cloud calls awid
  to issue certificates on behalf of the team.

### Issuance

Certificates are issued when a member joins a team:

1. Team controller invites agent (`aw id team invite`)
2. Agent accepts (`aw id team accept-invite <token>`)
3. Team controller signs certificate for the agent's did:key
4. Certificate stored at `.aw/team-cert.pem` on the agent's machine

Or: team controller adds member directly (`aw id team add-member`),
signs certificate, delivers it to the agent.

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
   `POST /v1/namespaces/{domain}/teams/{name}/revocations`
   with the `certificate_id`.
2. awid adds the entry to `team_revocations`.
3. Services refresh their cached revocation list within their TTL
   (recommended: 5-15 minutes).
4. The revoked certificate is rejected on next request after cache
   refresh.

The revocation list is small — it only grows when members are removed.
It can be pruned periodically (entries older than some threshold are
unlikely to be presented).

---

## Team key escrow for managed namespaces

For namespaces managed by aweb.ai (e.g., `juanre.aweb.ai`), the
team controller key is held in escrow by awid. This allows aweb-cloud
to issue certificates on behalf of managed teams without the human
holding the key locally.

The escrow key is encrypted with `AWID_TEAM_KEY_ENCRYPTION_KEY`
(AES-256-GCM, same pattern as custody key encryption).

awid exposes an internal endpoint for aweb-cloud to issue certificates
for managed teams:

```
POST /v1/namespaces/{domain}/teams/{name}/certificates/issue
Auth: parent controller DIDKey signature
Body: {
  "member_did_key": "did:key:z6Mk...",
  "member_did_aw": "did:aw:...",
  "member_address": "juanre.aweb.ai/alice",
  "alias": "alice",
  "lifetime": "permanent"
}
Response: { certificate JSON with signature }
```

For BYOD teams (acme.com), the team controller holds the key
locally and signs certificates themselves via `aw id team add-member`.

---

## awid database schema (complete, after teams)

```sql
-- Existing tables (unchanged)

CREATE TABLE did_aw_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did_aw          TEXT UNIQUE NOT NULL,
    current_did_key TEXT NOT NULL,
    server          TEXT,
    address         TEXT,
    handle          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    namespace_type  TEXT NOT NULL DEFAULT 'verified',
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
    did_aw          TEXT NOT NULL,
    current_did_key TEXT NOT NULL,
    reachability    TEXT NOT NULL DEFAULT 'public',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (domain, name)
);

-- New tables

CREATE TABLE teams (
    team_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    team_key_enc    BYTEA,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (domain, name)
);

CREATE TABLE team_revocations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(team_id),
    certificate_id  TEXT NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_id, certificate_id)
);

CREATE INDEX idx_team_revocations_team
    ON team_revocations (team_id, revoked_at);
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

# Team key escrow (for managed namespaces)
# AES-256-GCM key for encrypting/decrypting escrowed team controller keys.
# Required for managed namespaces (*.aweb.ai). Not needed for BYOD.
AWID_TEAM_KEY_ENCRYPTION_KEY=

# Custodial signing
# AES-256-GCM key for agent signing keys held in escrow.
AWID_CUSTODY_KEY=
```

---

## What awid does NOT do

| Concern | Owner |
|---------|-------|
| Store team member lists | Nobody — certificates are the proof |
| Renew certificates | Agent runtime or aweb-cloud |
| Manage API keys | Nobody — gone |
| Coordinate agents | aweb |
| Manage billing | aweb-cloud |
| Manage human accounts | aweb-cloud |
