# Trust Model

Status: **canonical trust and key-authority reference**. The conceptual
identity/team vocabulary lives in
[identity.md](https://github.com/awebai/aweb/blob/main/docs/identity.md); this
page answers which key authorizes each fact, who holds it, and what continuity
or recovery claim exists when it changes.

For protocol-level details of each signed envelope, see
[awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md) and
[aweb-sot.md](https://github.com/awebai/aweb/blob/main/docs/aweb-sot.md).
AWID stores public registry facts and signed assertions. It never holds the
private keys below or signs on behalf of an identity, namespace, or team. The
aweb coordination server verifies those facts; it is not controller authority.
A hosted operator may hold keys only for an explicitly hosted-authority or
custodial flow.

---

## Authority Graph

Three Ed25519 key types authorize different facts. They are related, but they
are not one ownership chain: a team controller certifies that an independently
held identity key is a member; it does not own, create, rotate, or recover that
identity key.

```
DNS (root for namespace control)
  |
  +-- Namespace controller key
        |-- creates/rotates team public-key records
        |-- assigns or replaces namespace/name addresses
        +-- delegates child namespace creation

Team controller key
  +-- signs/revokes membership certificates that bind member identity keys

Identity signing key
  |-- self-authorizes initial did:aw registration
  |-- retiring key authorizes global key rotation
  +-- signs messages and requests
```

The namespace controller can rotate a lost team controller because it owns the
team record. It cannot rotate somebody else's global identity key. It can move
an address to a replacement identity, which is a different and weaker
controller-authorized continuity claim.

Each key type can be **locally held** (self-controlled/self-custodial) or
**hosted-operator held** (hosted authority/custodial identity). Custody
determines who stores the private key and can perform authorized recovery, but
it does not change the key type's authority. Identity custody, team authority,
and coordination hosting are independent axes.

---

## Key Types

### 1. Namespace Controller Key

The authority over a DNS-verified domain.  Controls addresses, teams, and
team key rotation within the namespace.

| Aspect                   | Detail                                                                                                                                               |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Algorithm**            | Ed25519                                                                                                                                              |
| **Private key location** | Self-controlled/BYOT: `~/.awid/controllers/<domain>.key`. Hosted authority: held by the operator                                                         |
| **Public key location**  | awid `dns_namespaces.controller_did` + DNS TXT record (`_awid.<domain>`)                                                                             |
| **Authorizes**           | Namespace operations, child namespace creation (parent delegation), team creation/deletion, team key rotation, address create/delete/reassign        |
| **Created by**           | Self-controlled/BYOT: `aw id namespace prepare-controller` or first `aw id create` for a domain. Hosted authority: the operator                       |
| **Rotation**             | `aw id namespace rotate-controller` (requires DNS reverify)                                                                                          |
| **Recovery if lost**     | DNS reverify: DNS is the root of trust.  The `rotate-controller` command proves domain ownership via DNS TXT and re-establishes a new controller key |

For self-controlled namespaces, keep `~/.awid` safe and backed up. It contains
the namespace controller private key.

#### Parent delegation

A namespace controller can authorize child namespace creation. For example,
the `example.com` controller can create `agents.example.com`. AWID verifies
this by looking up the parent namespace and checking that the signer matches
the parent's `controller_did`.

This is the standard mechanism, not a hosted special case. Any namespace owner
can delegate child namespaces; a hosted operator uses the same public protocol
under the base domain it controls.

Authority flows downward: a namespace controller can rotate the team
controller key, but the team controller cannot rotate the namespace
controller key.

### 2. Team Controller Key

The authority over team membership.  Issues and revokes team certificates.

| Aspect                   | Detail                                                                                                                                                       |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Algorithm**            | Ed25519                                                                                                                                                      |
| **Private key location** | Self-controlled/BYOT: `~/.awid/team-keys/<domain>/<team>.key`. Hosted authority: held by the operator                                                        |
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
| **Public key location** | awid `did_aw_mappings.current_did_key` (for global identities).  Also embedded in the team certificate as `member_did_key` |
| **Authorizes** | Message signing, DID registration (identity-only `register_did`, no address), DID key rotation, identity-scoped auth (messaging routes), team-certificate auth (coordination routes, together with the team cert) |
| **Created by** | Self-custodial: `aw init` for a local workspace or `aw init --global --name <name>` for a global identity.  Custodial: the operator's dashboard |
| **Rotation** | Global self-custodial: `aw id rotate-key` requires the old key to sign. Local team-scoped: `aw team replace-key` requires the team controller and an exact old→new compare-and-swap. Custodial: operator re-generates server-side. |
| **Recovery if lost** | Local-controller/BYOT local identity: team-authorized `aw team replace-key`. Self-custodial global identity remains a gap (see [Identity Key Loss](#identity-key-loss)). Custodial: the operator's replace operation generates a new key, re-registers DID, reassigns address. |

#### Custody modes

The identity signing key has two custody modes:

- **Self-custodial**: the agent holds its own private key locally in
  `.aw/signing.key`.  Created from the CLI.  The private key never leaves
  the local machine.
- **Custodial**: an operator holds the private key on behalf of the agent.
  Created by an explicit hosted-custody flow for browser or service runtimes
  that do not have filesystem access. The operator signs on behalf of the
  identity.

The key type is the same — Ed25519, same operations, same authority.
Custody determines who stores the private key and who can perform
recovery.

### 4. E2E Message Encryption Key (separate from the authority chain)

E2E message v2 uses an X25519 encryption keypair that is distinct from the
Ed25519 identity signing key. It is not a fourth controller layer:

- the X25519 private key decrypts message content;
- the identity signing key authorizes the published encryption public-key
  assertion;
- AWID may publish a global identity's signed assertion, and aweb may publish a
  local member's signed assertion, but neither registry/service can substitute
  its own encryption key for the member's;
- self-custodial clients keep active and archived private keys under
  `.aw/encryption-keys/` and select the active key in `.aw/encryption.yaml`;
- `assertion_custody=self` and `assertion_custody=hosted_custodial` describe who
  controls decryption capability; they do not grant namespace or team authority.

Losing an archived encryption private key makes messages encrypted to that key
unrecoverable. Signing-key recovery or certificate reissuance does not recover
old ciphertext. See
[e2e-messaging-contract.md](https://github.com/awebai/aweb/blob/main/docs/e2e-messaging-contract.md)
for the normative encryption protocol.

#### Identity vs address authority

The identity signing key authorizes the identity-side operations
(`register_did`, `rotate_key`) and nothing else. It does not authorize
address creation. An address under `domain/name` is created by the
namespace controller of `domain` — either the BYOD controller of
`domain`, or the hosted operator for managed namespaces.

This split is load-bearing. It means a `did_aw` can exist without
any address (local-to-global upgrades, cross-namespace
memberships), and a managed address can be assigned to a
self-custodial `did_aw` without the hosted operator ever touching
the identity key. The awid-side invariant — `did_aw` must be
registered before any address can be bound to it — enforces the
ordering; see [`awid-sot.md`](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md#identity-operations).

A single `did_aw` may hold multiple addresses. Address choice is therefore
not an identity-auth decision. For team-scoped work, the active team
certificate selects the sender address via `member_address`; in OSS aweb
this is stored on the team-scoped `agents` row for that membership.
Identity-auth verification proves the key binding only and must not infer
a canonical address by listing all addresses for the `did_aw`.

For mail/chat routing, address reads, recipient binding, and the
boundary between awid authority and aweb local routing state, see
[`identity-messaging-contract.md`](https://github.com/awebai/aweb/blob/main/docs/identity-messaging-contract.md).

---

## Key Storage Summary

### Self-controlled (BYOT / CLI)

```
~/.awid/controllers/<domain>.key       # Namespace controller key
~/.awid/team-keys/<domain>/<team>.key  # Team controller key
<repo>/.aw/signing.key                      # Identity signing key (per workspace)
<repo>/.aw/team-certs/<team_id>.pem         # Team membership certificate (not a key)
```

Back up `~/.awid` after creating a namespace or team controller. These keys
control namespace addresses and team membership.

### Hosted authority and custodial identity

Controller keys and custodial identity keys are held by the hosted operator for
the explicit resources it controls. Parent delegation creates hosted child
namespaces under the operator's base domain. This custody does not extend to a
customer-controlled BYOT namespace/team or make the aweb server key authority.

---

## Recovery and Replacement Paths

Recovery follows the authority for the affected fact, not a universal parent
chain. Team-controller recovery preserves the team record. Global signing-key
rotation preserves `did:aw` only when the retiring key signs. Address replacement
creates a different stable identity and preserves only controller-authorized
address continuity.

| Key lost                  | Recovered by                    | Mechanism                                                  | Status          |
|---------------------------|---------------------------------|------------------------------------------------------------|-----------------|
| Namespace controller      | DNS ownership                   | `aw id namespace rotate-controller` — DNS reverify         | **Implemented** |
| Team controller           | Namespace controller            | `POST /v1/namespaces/{domain}/teams/{name}/rotate` at awid | **Implemented** |
| Identity (custodial)      | Custody operator plus the actual address/team controllers | Replace — new keypair and new DID; authorized controllers reassign address and membership | **Operator-specific** |
| Local identity (self-custodial, local-controller team) | Team controller | `aw team replace-key` — roster CAS + certificate replacement + audit | **Implemented** |
| Global identity (self-custodial) | Namespace + team controllers | Stable-identity/address recovery flow | **Gap** |

---

## Identity Key Loss

### Custodial global identity

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

A hosted operator may provide this operation for custodial identities and
hosted addresses it manages. A BYOT address still requires the customer's
namespace controller, and BYOT membership still requires the customer's team
controller.

### Self-custodial global identity (CLI-created)

**No recovery path exists today.**

- `aw id rotate-key` requires the old key to sign the rotation — useless
  if the key is lost.
- Hosted account recovery applies only when the identity was enrolled in that
  operator's custody/recovery system and the required address/team authorities
  cooperate.
- There is no OSS CLI command for global archive or controller-authorized
  replacement.
- A CLI-only user without a separately established recovery authority cannot
  recover stable-identity continuity after losing the signing key.

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

### Local identity

A local identity has no stable identifier above its Ed25519 `did:key`: the key
**is the identity**. Preserve the complete `.aw/` directory when moving the
workspace between machines. Regenerating `.aw/signing.key` without an
authorized replacement creates a new identity; correspondents with the old key
pinned will honestly report an identity mismatch.

For a local-controller/BYOT team, a human operator holding the team controller
can authorize the explicit transition:

```bash
aw team replace-key alice \
  --old-did-key did:key:OLD \
  --home agents/instances/alice \
  --generate-new-key
```

The operation compare-and-swaps the service roster, records the controller DID
and old→new transition in `audit_log`, revokes the old team certificate, mints
and registers the replacement, installs it in `--home`, and refreshes the local
E2E encryption-key assertion under the new signing identity. The generated key
is written only when `.aw/signing.key` is absent; an existing key is never
silently overwritten. For a compromised key, back it up and remove it
deliberately before using `--generate-new-key`. It never accepts an old-member-key
self-service handover. Without `--home`, the operator must pass
`--old-cert-id`; the command outputs the new public certificate with placement
instructions. Phase 1 supports locally held team-controller keys only. Hosted
authority owner/admin replacement is not part of the current OSS CLI path; until
a hosted operator exposes an authorized equivalent, it requires that operator's
support.

---

## Trust Verification

Message trust has two layers: Ed25519 signature/recipient-binding verification,
then continuity handling for a globally addressed sender.

### Threat-model rulings (2026-08-17)

Two rulings, made explicitly so they are design constraints rather than
implicit assumptions:

**Partial-service compromise is in scope.** The aweb service is multiple
components (ingest, message store, roster, registry client) with different
attack surfaces, and the trust model does not assume they fail only together.
Consequences: a reader's fresh roster re-resolution of a local sender is a
load-bearing cross-check against a compromised message store or ingest
component, not a redundant read, and must not be removed in favor of trusting
stored attribution alone. Any future verdict that rests on the service's own
attestation instead of a completed reader-side check must carry a distinct
status (for example `verified_server_attested`) and must still fail on a
roster mismatch whenever the reader can obtain the roster. Plain `verified`
always means the reader completed the binding and continuity checks itself.

**The revocation source-suppression residual is accepted, and named.** A
verifier learns revocation state only by asking a registry (or, for local
members, the team's aweb service). Signed artifacts prove presence; nothing in
this protocol proves absence. An authority that keeps serving old but
cryptographically valid state — maliciously, or as innocently as a restore
from backup — can suppress a revocation the verifier has never seen, for as
long as the verifier has no second channel. Client cache ceilings bound the
verifier's own staleness, not the source's honesty. Until the exit ladder
below lands, **revocation freshness rests on the honesty and availability of
the consulted registry operator.** That is a named trust assumption of the
current system.

The client half is quantified: verifiers cache a team's revocation list for at
most 60 seconds (hard worst case 120 seconds through the stale-while-revalidate
window), matching the federation authority reuse ceiling. Against an honest
registry, a revocation therefore takes effect on enforcement within about a
minute. Raising that constant is a trust-model change, not a tuning decision.

The committed exit ladder, in order:

1. **Hash-chained revocation log with client-persisted checkpoints** — the
   same anti-rollback treatment DID logs already have, applied to revocations;
   folded into the certificate-chain verification protocol when that work
   proceeds.
2. **Witness/transparency mechanisms** — deferred until the deployment is
   genuinely multi-operator; before that a witness set adds ceremony, not
   security.

Certificate expiry was previously the ladder's first rung and was **removed
by owner decision (2026-08-17)** — not deferred: it is not part of the
architecture. Certificates remain valid until revoked, and revocation is the
sole end of membership authority. Stated plainly, because this section
exists to make trust assumptions explicit: expiry was the only mechanism
that put an **unconditional time bound** on the suppression residual above;
the remaining ladder items are detection and corroboration mechanisms, not
a replacement bound. With expiry removed, a suppressed revocation has no
architectural ceiling — the residual is accepted as unbounded, resting
entirely on the operator trust assumption already named.

The full assessment and its adversarial review live in
[drafts/local-sender-verification-authority.md](drafts/local-sender-verification-authority.md)
and on task `aweb-abfm`.

For cross-registry ingress, the receiving service's strict external-address
path is stronger and separate from general client TOFU/cache behavior. It
selects authority from the client-signed address, not the receiver's home
registry, and requires DNS controller, exact namespace/address/DID/key/origin,
genesis-anchored log evidence, and a PostgreSQL checkpoint/cohort commit.
`OK_DEGRADED`, a general cache hit, or a process-local pin cannot authorize.
The receiver may reuse a complete cohort for at most 60 seconds, but an
external authority can suppress an unseen change by continuing to serve old
valid evidence; this protocol therefore makes no global freshness SLA.

### TOFU pins and durable continuity

For global identities, current Go and TypeScript clients keep an address-to-pin
index. A first verified contact is pinned by `did:aw` when a valid stable id is
available, otherwise by the observed `did:key`. A stable-identity pin also keeps
the last verified current key and the highest verified DID-log sequence/hash so
rollback detection survives process restarts.

Local single-team identities skip persistent global TOFU pinning. Their current
key is refreshed against the live team roster; a changed key that cannot be
reconciled is not silently accepted.

The visible outcomes mean:

- `verified` — signature and recipient binding passed, and any new/changed
  continuity state was durably committed;
- `verified_custodial` — the same verification result with hosted-custodial
  sender metadata; it is not stronger cryptography;
- `verification_stale` — the signature may be valid, but authoritative
  continuity/freshness could not be completed or a required new checkpoint
  could not be persisted; it must not overwrite a pin;
- `identity_mismatch` — recipient binding, stable-key verification, rollback
  protection, or the pinned address identity conflicts;
- `unverified` — the signature/identity input was absent or not verifiable.

A failed first pin, rotation update, replacement, or DID-log checkpoint write is
not reported as verified: continuity that did not reach durable storage would be
forgotten on restart. Raw pin-store parser behavior is shared through
[`vectors/pin-store-raw-wire-v1.json`](https://github.com/awebai/aweb/blob/main/docs/vectors/pin-store-raw-wire-v1.json),
including explicitly recorded cross-runtime compatibility differences.

Recipients can authorize a continuity change through two distinct paths:

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
changed.  This is weaker trust than signed rotation — it says "the namespace
owner vouches for this replacement" rather than "the old identity vouches for
this successor."

**The controller-signed announcement is required, not advisory.** A client that
holds a pin for an address refuses to move it to a different `did:aw` without
one, and reports `identity_mismatch` instead. A valid DID log for the incoming
identity is *never* sufficient on its own: the log proves `did:aw → did:key`,
not `address → did:aw`, and an attacker who legitimately owns their own `did:aw`
has a wholly valid log. The controller's authority is anchored in the address's
`_awid` DNS TXT `controller=` field rather than in the registry response, so a
registry response alone cannot forge it. Strict receiving authority also checks
that the current DNS controller matches the proof and freshly resolves the new
address/DID/key/origin chain.

A controller-signed announcement proves namespace intent; it does not silently
transfer a recipient's trust relationship. For an identity-bound contact, an
in-place old-DID to new-DID move requires all of: the canonical controller
proof, current strict authority for the new DID, an exact-old compare-and-swap,
and an authenticated request by the contact owner as explicit acceptance.
Address-only legacy contacts remain inert until their owner explicitly binds
them to the freshly resolved DID. Deleting a contact does not rebind or transfer
it; any later new-contact creation is a distinct strict resolution and owner
acceptance. Address reassignment by itself never transfers the old contact or
conversation.

Operationally this means an address handover without controller proof is
refused, and even valid controller proof cannot create or transfer a contact
without recipient acceptance. Publishing the proof, changing the address row,
and accepting the relationship are distinct operations.

---

## Further Reading

- [aweb-sot.md](https://github.com/awebai/aweb/blob/main/docs/aweb-sot.md) — identity model, authentication, lifecycle
- [awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md) — registry API, signed envelopes, certificate format
- [identity.md](https://github.com/awebai/aweb/blob/main/docs/identity.md) — identity concepts and TOFU model
- [identity-key-verification.md](https://github.com/awebai/aweb/blob/main/docs/identity-key-verification.md) — DID key verification rules
