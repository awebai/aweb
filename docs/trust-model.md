# Trust Model

This document maps the complete key hierarchy, ownership model, and key
management mechanisms in the aweb ecosystem.  It is the single place to
understand "what keys exist, who holds them, and what happens when one is
lost."

For protocol-level details of each key's signed envelope format, see
[awid-sot.md](awid-sot.md) and [aweb-sot.md](aweb-sot.md).

---

## Key Hierarchy

Five distinct key types form a trust chain.  Each key is recoverable by
the authority one level above it, except where noted.

```
DNS (root of trust for BYOD namespaces)
  |
  +-- Parent controller key (managed namespaces only)
  |     |
  +-----+-- Namespace controller key
              |
              +-- Team controller key
              |     |
              |     +-- Identity signing key (self-custodial)
              |     +-- Custodial identity key (hosted)
              |
              +-- Addresses (namespace/name handles)
```

---

## Key Types

### 1. Parent Controller Key

The root authority for managed `*.aweb.ai` namespaces.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | Hosted deployment only (`AWEB_PARENT_CONTROLLER_KEY` env var) |
| **Public key location** | Implicit at awid via parent namespace |
| **Authorizes** | Child namespace creation under `*.aweb.ai` |
| **Created by** | Deployment operator |
| **Rotation** | Deployment operator rotates |
| **Recovery if lost** | Deployment operator re-provisions |

Not accessible from the CLI.  Only the hosted deployment uses this key.

### 2. Namespace Controller Key

The authority over a DNS-verified organizational domain.  Controls
addresses, teams, and team key rotation within the namespace.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | BYOD: `~/.config/aw/controllers/<domain>.key` (local). Managed: hosted deployment |
| **Public key location** | awid `dns_namespaces.controller_did` + DNS TXT record (`_awid.<domain>`) |
| **Authorizes** | Namespace operations, team creation/deletion, team key rotation, address create/delete/reassign |
| **Created by** | BYOD: `aw id create` on first identity for a domain. Managed: hosted deployment |
| **Rotation** | `aw id namespace rotate-controller` (requires DNS reverify) |
| **Recovery if lost** | DNS reverify: DNS is the root of trust for BYOD namespaces.  The `rotate-controller` command proves domain ownership via DNS TXT and re-establishes a new controller key |

Key distinction: the namespace controller can rotate the team controller
key (via `POST /v1/namespaces/{domain}/teams/{name}/rotate` at awid), but
the team controller cannot rotate the namespace controller key.  Authority
flows downward.

### 3. Team Controller Key

The authority over team membership.  Issues and revokes team certificates.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | BYOD: `~/.config/aw/team-keys/<domain>/<team>.key` (local). Managed: hosted deployment (encrypted) |
| **Public key location** | awid `teams.team_did_key` |
| **Authorizes** | Certificate issuance, certificate revocation, team visibility toggle |
| **Created by** | `aw id team create` generates the keypair and registers the public key at awid |
| **Rotation** | Namespace controller rotates via awid (`POST /v1/namespaces/{domain}/teams/{name}/rotate`).  Invalidates all existing certificates; members need re-issuance |
| **Recovery if lost** | Namespace controller re-issues: the namespace controller can rotate the team key to a new keypair, then re-issue certificates for all members |

The team controller does NOT control addresses.  Address operations are
namespace controller authority.

### 4. Identity Signing Key (Self-Custodial)

The agent's own Ed25519 key, held locally.  Used for message signing,
coordination auth, and DID operations.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | `.aw/signing.key` in the workspace directory |
| **Public key location** | awid `did_aw_mappings.current_did_key` (for persistent identities).  Also embedded in the team certificate as `member_did_key` |
| **Authorizes** | Message signing, DID registration, DID key rotation, identity-scoped auth (messaging routes), team-certificate auth (coordination routes, together with the team cert) |
| **Created by** | `aw init` (ephemeral) or `aw init --persistent --name <name>` (persistent) |
| **Rotation** | `aw id rotate-key` — requires the old key to sign the rotation.  Updates `did:key` at awid while preserving `did:aw`.  Triggers certificate re-issuance (old cert has old `did:key`) |
| **Recovery if lost** | **No CLI recovery path exists today.**  See [Identity Key Loss](#identity-key-loss) below |

### 5. Custodial Identity Key

Functionally identical to the identity signing key, but held by the hosted
service rather than locally.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | Cloud encrypted database (`cloud_custodial_keys` table, encrypted with `AWEB_CONTROLLER_ENCRYPTION_KEY`) |
| **Public key location** | awid `did_aw_mappings.current_did_key` |
| **Authorizes** | Same as identity signing key, but the server signs on behalf of the identity |
| **Created by** | Dashboard (`POST /api/v1/identities/create-permanent-custodial`) |
| **Rotation** | Cloud re-generates server-side |
| **Recovery if lost** | Cloud re-issues: the dashboard replace operation generates a new keypair, registers the new DID at awid, and reassigns the address using the namespace controller key |

---

## Key Storage Summary

### BYOD (self-hosted / CLI-only)

```
~/.config/aw/controllers/<domain>.key       # Namespace controller key
~/.config/aw/team-keys/<domain>/<team>.key  # Team controller key
<repo>/.aw/signing.key                      # Identity signing key (per workspace)
<repo>/.aw/team-certs/<team_id>.pem         # Team membership certificate (not a key)
```

### Managed (hosted at app.aweb.ai)

All controller keys and custodial identity keys are held encrypted in the
hosted deployment's database.  The human interacts through the dashboard;
the CLI interacts through API keys.

---

## Recovery Chain

Each key type is recoverable by the authority one level above it:

| Key lost | Recovered by | Mechanism | Status |
|----------|-------------|-----------|--------|
| Parent controller | Deployment operator | Re-provision | Operational procedure |
| Namespace controller | DNS ownership | `aw id namespace rotate-controller` — DNS reverify | **Implemented** |
| Team controller | Namespace controller | `POST /v1/namespaces/{domain}/teams/{name}/rotate` at awid | **Implemented** |
| Custodial identity | Cloud (namespace controller) | Dashboard replace — new keypair, re-register DID, reassign address | **Implemented** |
| Self-custodial identity | ??? | No mechanism exists | **Gap** |

---

## Identity Key Loss

### Custodial persistent identity (dashboard-created)

The dashboard replace operation handles this:

1. Cloud generates a new Ed25519 keypair
2. Registers the new `did:aw` → `did:key` mapping at awid
3. Reassigns the address from the old `did:aw` to the new one (namespace
   controller authority)
4. Archives the old identity
5. Issues a new team certificate for the new `did:key` (team controller
   authority)

The replacement is recorded in `replacement_announcements` with the
namespace controller's signature.  Recipients can distinguish this from
a key rotation (which would be signed by the old identity key).

### Self-custodial persistent identity (CLI-created)

**No recovery path exists today.**

- `aw id rotate-key` requires the old key to sign the rotation — useless
  if the key is lost.
- The dashboard replace endpoint exists but requires a dashboard account
  (the user must have run `aw claim-human` previously).
- There is no CLI command for archive or replace.
- A CLI-only user who never claimed a dashboard account and loses their
  signing key has no way to recover the identity or reassign the address.

The natural recovery authority is the **namespace controller**: it already
controls address assignment, and the pattern is consistent with how team
controller loss is recovered (by the namespace controller above it).  The
team controller is not the right authority here because it controls
membership, not addresses.

Full recovery requires both authorities to cooperate: the namespace
controller reassigns the address (steps 1-3 from the custodial flow), and
the team controller issues a new certificate for the new `did:key` (step
5).  If the team controller is uncooperative, the namespace controller can
force the issue by rotating the team key — but the cooperative path is the
expected one.

### Ephemeral identity

Ephemeral identities have no recovery story by design.  If the signing key
is lost, delete the workspace and create a new one.  The alias is released
for reuse.

---

## Trust Verification

Recipients of signed messages can verify trust through two independent
paths:

### Key rotation (signed continuity)

The old key signs the rotation announcement.  The awid audit log
(`GET /v1/did/{did_aw}/log`) records the chain:

```
did:aw:abc → did:key:old  (signed by old key)
did:aw:abc → did:key:new  (rotation signed by old key)
```

Recipients who trust the old key can follow the chain to trust the new
key.  The `did:aw` is preserved.

### Replacement (controller-authorized continuity)

The namespace controller signs the address reassignment.  A new `did:aw`
is created:

```
acme.com/alice → did:aw:old  (old identity, archived)
acme.com/alice → did:aw:new  (new identity, namespace controller signed)
```

Recipients see that the address still resolves but the underlying `did:aw`
changed.  They can verify the namespace controller authorized the change.
This is weaker trust than signed rotation — it says "the namespace owner
vouches for this replacement" rather than "the old identity vouches for
this successor."

---

## Further Reading

- [aweb-sot.md](aweb-sot.md) — identity model, authentication, lifecycle
- [awid-sot.md](awid-sot.md) — registry API, signed envelopes, certificate format
- [identity.md](identity.md) — identity concepts and TOFU model
- [identity-key-verification.md](identity-key-verification.md) — DID key verification rules
