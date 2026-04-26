# Trust Model

This document maps the complete key hierarchy, ownership model, and key
management mechanisms in the aweb ecosystem.  It is the single place to
understand "what keys exist, who holds them, and what happens when one is
lost."

For protocol-level details of each key's signed envelope format, see
[awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md) and [aweb-sot.md](https://github.com/awebai/aweb/blob/main/docs/aweb-sot.md).

---

## Key Hierarchy

Three key types form a trust chain.  DNS is the root of trust.  Each key
is recoverable by the authority one level above it.

```
DNS (root of trust)
  |
  +-- Namespace controller key
  |     |
  |     +-- Team controller key
  |     |     |
  |     |     +-- Identity signing key
  |     |
  |     +-- Addresses (namespace/name handles)
  |
  +-- Parent delegation (namespace controllers can authorize
        child namespace creation, e.g. aweb.ai → juan.aweb.ai)
```

Each key type has two custody modes: **locally held** (BYOD / CLI) or
**deployment held** (managed / hosted).  Custody determines who stores the
private key and who can perform recovery, but the key type and its
authority are the same regardless of custody.

---

## Key Types

### 1. Namespace Controller Key

The authority over a DNS-verified domain.  Controls addresses, teams, and
team key rotation within the namespace.

| Aspect                   | Detail                                                                                                                                               |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Algorithm**            | Ed25519                                                                                                                                              |
| **Private key location** | BYOD: `~/.config/aw/controllers/<domain>.key`. Managed: held by the operator (e.g., app.aweb.ai)                                                     |
| **Public key location**  | awid `dns_namespaces.controller_did` + DNS TXT record (`_awid.<domain>`)                                                                             |
| **Authorizes**           | Namespace operations, child namespace creation (parent delegation), team creation/deletion, team key rotation, address create/delete/reassign        |
| **Created by**           | BYOD: `aw id create` on first identity for a domain. Managed: the operator on behalf of the user                                                     |
| **Rotation**             | `aw id namespace rotate-controller` (requires DNS reverify)                                                                                          |
| **Recovery if lost**     | DNS reverify: DNS is the root of trust.  The `rotate-controller` command proves domain ownership via DNS TXT and re-establishes a new controller key |

#### Parent delegation

A namespace controller can authorize child namespace creation.  For
example, the `aweb.ai` namespace controller can create `juan.aweb.ai` or
`myteam.aweb.ai`.  awid verifies this by looking up the parent namespace
(`aweb.ai`) and checking that the signer matches the parent's
`controller_did`.

This is the standard mechanism, not a special case.  Any namespace owner
can delegate child namespaces.  For example, the operator at app.aweb.ai
holds the `aweb.ai` namespace controller key and uses standard parent
delegation to create managed child namespaces like `myteam.aweb.ai`.

Authority flows downward: a namespace controller can rotate the team
controller key, but the team controller cannot rotate the namespace
controller key.

### 2. Team Controller Key

The authority over team membership.  Issues and revokes team certificates.

| Aspect                   | Detail                                                                                                                                                       |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Algorithm**            | Ed25519                                                                                                                                                      |
| **Private key location** | BYOD: `~/.config/aw/team-keys/<domain>/<team>.key`. Managed: held by the operator (encrypted)                                                                |
| **Public key location**  | awid `teams.team_did_key`                                                                                                                                    |
| **Authorizes**           | Certificate issuance, certificate revocation, team visibility toggle                                                                                         |
| **Created by**           | `aw id team create` generates the keypair and registers the public key at awid                                                                               |
| **Rotation**             | Namespace controller rotates via awid (`POST /v1/namespaces/{domain}/teams/{name}/rotate`).  Invalidates all existing certificates; members need re-issuance |
| **Recovery if lost**     | Namespace controller re-issues: the namespace controller can rotate the team key to a new keypair, then re-issue certificates for all members                |

The team controller does NOT control addresses.  Address operations are
namespace controller authority.

The team controller does select which already-registered address is bound
to a team membership certificate. That `member_address` is not a global
property of the identity; it is a claim about how this member appears when
acting in this team. awid validates that the selected address resolves to
the certificate's `member_did_aw`.

### 3. Identity Signing Key

The agent's Ed25519 key.  Used for message signing, coordination auth, and
DID operations.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Private key location** | Self-custodial: `.aw/signing.key` in the workspace directory.  Custodial: operator's encrypted storage |
| **Public key location** | awid `did_aw_mappings.current_did_key` (for persistent identities).  Also embedded in the team certificate as `member_did_key` |
| **Authorizes** | Message signing, DID registration (identity-only `register_did`, no address), DID key rotation, identity-scoped auth (messaging routes), team-certificate auth (coordination routes, together with the team cert) |
| **Created by** | Self-custodial: `aw init` (ephemeral) or `aw init --persistent --name <name>` (persistent).  Custodial: the operator's dashboard |
| **Rotation** | Self-custodial: `aw id rotate-key` — requires the old key to sign.  Custodial: operator re-generates server-side |
| **Recovery if lost** | Self-custodial: **no CLI recovery path exists today** (see [Identity Key Loss](#identity-key-loss)).  Custodial: the operator's replace operation generates a new key, re-registers DID, reassigns address |

#### Custody modes

The identity signing key has two custody modes:

- **Self-custodial**: the agent holds its own private key locally in
  `.aw/signing.key`.  Created from the CLI.  The private key never leaves
  the local machine.
- **Custodial**: an operator holds the encrypted private key on behalf
  of the agent.  Created from the operator's dashboard (e.g.,
  app.aweb.ai) for hosted or browser MCP runtimes that don't have
  filesystem access.  The operator signs on behalf of the identity.

The key type is the same — Ed25519, same operations, same authority.
Custody determines who stores the private key and who can perform
recovery.

#### Identity vs address authority

The identity signing key authorizes the identity-side operations
(`register_did`, `rotate_key`) and nothing else. It does not authorize
address creation. An address under `domain/name` is created by the
namespace controller of `domain` — either the BYOD controller of
`domain`, or the hosted operator for managed namespaces.

This split is load-bearing. It means a `did_aw` can exist without
any address (ephemeral-turned-durable upgrades, cross-namespace
memberships), and a managed address can be assigned to a
self-custodial `did_aw` without the hosted operator ever touching
the identity key. The awid-side invariant — `did_aw` must be
registered before any address can be bound to it — enforces the
ordering; see [`awid-sot.md`](awid-sot.md#identity-operations).

A single `did_aw` may hold multiple addresses. Address choice is therefore
not an identity-auth decision. For team-scoped work, the active team
certificate selects the sender address via `member_address`; in OSS aweb
this is stored on the team-scoped `agents` row for that membership.
Identity-auth verification proves the key binding only and must not infer
a canonical address by listing all addresses for the `did_aw`.

For mail/chat routing, private address reads, recipient binding, and the
boundary between awid authority and aweb local routing state, see
[`identity-messaging-contract.md`](identity-messaging-contract.md).

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

Controller keys and custodial identity keys are held encrypted by the
operator.  The `aweb.ai` namespace controller key enables parent
delegation for managed child namespaces.  Child namespace controller keys
are generated per-organization and stored encrypted.  The human interacts
through the dashboard; the CLI interacts through API keys.

---

## Recovery Chain

Each key type is recoverable by the authority one level above it:

| Key lost                  | Recovered by                    | Mechanism                                                  | Status          |
|---------------------------|---------------------------------|------------------------------------------------------------|-----------------|
| Namespace controller      | DNS ownership                   | `aw id namespace rotate-controller` — DNS reverify         | **Implemented** |
| Team controller           | Namespace controller            | `POST /v1/namespaces/{domain}/teams/{name}/rotate` at awid | **Implemented** |
| Identity (custodial)      | Operator (namespace controller) | Replace — new keypair, re-register DID, reassign address   | **Implemented** |
| Identity (self-custodial) | ???                             | No mechanism exists                                        | **Gap**         |

---

## Identity Key Loss

### Custodial persistent identity

The operator's replace operation handles this:

1. Generate a new Ed25519 keypair
2. Register the new `did:aw` → `did:key` mapping at awid
3. Reassign the address from the old `did:aw` to the new one (namespace
   controller authority)
4. Archive the old identity
5. Issue a new team certificate for the new `did:key` (team controller
   authority)

The replacement is recorded in `replacement_announcements` with the
namespace controller's signature.  Recipients can distinguish this from
a key rotation (which would be signed by the old identity key).

The app.aweb.ai dashboard provides this operation for custodial identities
it manages.

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

- [aweb-sot.md](https://github.com/awebai/aweb/blob/main/docs/aweb-sot.md) — identity model, authentication, lifecycle
- [awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md) — registry API, signed envelopes, certificate format
- [identity.md](https://github.com/awebai/aweb/blob/main/docs/identity.md) — identity concepts and TOFU model
- [identity-key-verification.md](https://github.com/awebai/aweb/blob/main/docs/identity-key-verification.md) — DID key verification rules
