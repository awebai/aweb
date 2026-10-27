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

Three controller roles exist, each with its own scope:

- **Parent controller key** (`*.aweb.ai`): managed by the hosted deployment,
  signs namespace registrations under managed domains, and may also be the
  registered namespace controller for those hosted children
- **Namespace controller key**: signs namespace operations and team
  creation under a specific namespace; held by the namespace owner (BYOD)
  or by the hosted deployment (managed). A hosted child may reuse its parent
  controller key rather than introducing a distinct child key.
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

Public identity and namespace read endpoints (`GET /v1/namespaces/{domain}`,
`GET /v1/did/{did_aw}/key`, etc.) are rate-limited and do not require
signatures. Team reads follow team visibility: public teams are anonymous;
private-team metadata, enumeration, certificate history, member lookup, and
revocations require a controller or unrevoked-member path signature, or the
trusted same-operator service credential described below. The per-certificate
`/certificates/{certificate_id}/status` read is the narrow anonymous exception,
including for private teams; it exposes only the four facts documented below.
The team-server record and the principal-attestation record reads (custodians,
custody, person) are likewise anonymous, each by exact key with one identical
404, as documented below. Identity-private
reads and certificate-blob fetch have their separately documented
authentication requirements.

An AWID service used by aweb must configure the same high-entropy
`AWID_SERVICE_TOKEN` as the aweb server (standalone AWID deployments that do not
serve aweb may omit it). The aweb RegistryClient sends that bearer
secret in `X-AWID-Service-Token` only to its exact configured home registry;
it never forwards the credential to a DNS-discovered external registry. AWID
uses constant-time comparison. A matching credential is a confidential
same-operator read capability: it may read and enumerate private-team metadata,
certificate history, member references, and revocations so the aweb server can
verify and reconcile memberships without holding every member key. It also
exempts all 19 registry GET read buckets from public-IP rate limits: DID key,
addresses, head, full and log; namespace get/list; address get/list; A2A
publication get; team get/list and member lookup; certificate list/fetch/status;
attestation record get and signed-records list; and revocations. The exemption does not change identity-private or certificate-blob
authentication. The same credential also exempts exactly six provisioning
write buckets from public-IP rate limits: `did_register` (POST `/v1/did`),
`namespace_register` (POST `/v1/namespaces`), `did_encryption_key_publish`
(POST `/v1/did/{did_aw}/encryption-key`), `team_create`
(POST `/v1/namespaces/{domain}/teams`), `certificate_register`
(POST `/v1/namespaces/{domain}/teams/{name}/certificates`), and
`address_register` (POST `/v1/namespaces/{domain}/addresses`). DID proofs,
namespace controller signatures and DNS or parent authorization, and
identity-signed encryption-key assertions remain required. Team creation and
address binding retain namespace-controller authority; certificate registration
retains team-controller authorization, member/address binding checks and
verification of any supplied signed certificate blob. The credential also
exempts three controller-signed team writes: `team_update`
(POST `/v1/namespaces/{domain}/teams/{name}/visibility`), `team_delete`
(DELETE `/v1/namespaces/{domain}/teams/{name}`) and `certificate_revoke`
(POST `/v1/namespaces/{domain}/teams/{name}/certificates/revoke`). Visibility
changes and revocation retain team-controller authorization; deletion retains
namespace-controller authorization and its refusal while active certificates
remain. It also exempts the principal-attestation record publishes (PUT
`/v1/namespaces/{domain}/teams/{name}/custodians/{custodian_id}` and
`…/certificates/{certificate_id}/custody|person`) from both their buckets, so a
custodial deployment's backfill is not throttled; the team-controller signature
is still required. Signed team-server record publication (PUT
`/v1/namespaces/{domain}/teams/{name}/server`) is also exempt from its
`team_server_publish` bucket; the current team-key signature remains required.
All other write buckets remain rate-limited even with a matching token.
Public callers keep the existing 10/hour DID, namespace and team creation
limits and 30/hour encryption-key, certificate and address registration limits.
Visibility changes and team deletion allow 300/hour and certificate revocation
1000/hour per IP: each already needs a controller signature, so the public
budget only stops a runaway client. Principal-attestation record publishes
allow 3000/hour per IP before authentication, and 2500/hour per team, charged
only after the team-controller signature verifies, so unauthenticated traffic
cannot spend a team's allowance. A 1,000-certificate backfill, about 2,000
records, fits within one hour.
It never authorizes a write, and must not be shared with
clients or sent to a discovered external registry. Missing credentials use the
normal visibility and public-IP rules. A wrong presented credential grants no
private read access, uses those limits, and emits the stable
`awid_service_credential_rejected` telemetry event without logging the secret.
An unconfigured deployment accepts no token and keeps the public-IP limits.

Each exempted request increments a process-local counter for its fixed bucket
name. AWID emits `event=awid_service_exempt metric=awid_service_exempt
value=<count> bucket=<name>` at counts 1, 2, 4, 8 and subsequent powers of two,
providing positive evidence that the shared credential matches without logging
every request. Values are cumulative per bucket for that application process
and reset on restart; they are not per-event increments or a cross-worker total.
The event contains no credential, client IP or identity.

### Client IP rate attribution

AWID uses the socket peer for public rate-limit keys by default. To enable
forwarded client attribution, configure both `AWEB_CF_EDGE_CIDRS` and
`AWEB_TRUSTED_PROXY_CIDRS`. Each accepts a JSON array of CIDR strings, or a
comma- or pipe-separated list. Both lists must be nonempty and every entry
valid; an invalid entry invalidates the whole list. Empty or invalid settings
retain the socket-peer key.

Forwarded headers are trusted only from the configured trusted proxy range.
The rightmost entry across all `X-Forwarded-For` field lines must be in a
configured CF edge range. AWID then walks right to left past trusted proxy and
CF hops to the client. A malformed chain or a chain containing only trusted
hops uses the socket peer. `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` and
the retired `AWEB_TRUST_PROXY_HEADERS` setting do not select a rate key.

On Render, the configured proxy range includes our first-party private
services. These callers are trusted by assumption and may choose their rate
attribution, including by fabricating an entire CF-looking chain. CF suffix
membership is not independent ingress authentication. This model requires the
private network to be restricted to the operator's services; an operator with
untrusted private callers needs a different ingress trust boundary. The ASGI
host must preserve the socket peer: keep Uvicorn's `FORWARDED_ALLOW_IPS` at its
loopback default rather than adding private ranges or `*`.

This selects rate-limit buckets only. Service-token exemptions and route
authentication and write authority are unchanged. The Cloud resolver remains
separate because its optional peer gate and tolerant CIDR parsing differ.

---

## Namespaces

DNS-verified organizational domains. `acme.com`, `juanre.aweb.ai`.
The exact-match reserved namespace `local` is also allowed for local
development/bootstrap without DNS verification; after creation it behaves
like any other namespace.

```
POST   /v1/namespaces                  Create (controller auth)
GET    /v1/namespaces/{domain}          Read (public)
PUT    /v1/namespaces/{domain}          Replace controller key (new-key proof)
DELETE /v1/namespaces/{domain}          Delete (controller auth)
```

The identity-tree contract adds a continuity-preserving
[`POST /v1/namespaces/{domain}/rotate`](id-certificates.md#continuity-preserving-namespace-rotation-new-operation),
with previous- and new-key proofs. This is new work; the released PUT remains
key-loss recovery. Its epoch and pre-upgrade first-registration rules are fixed
in that contract.

AWID keeps each domain's root-key history in `id_namespace_epochs`. Every
epoch was proven by exact `_awid.<domain>` DNS on an explicit act. The first
registration, re-registration after deletion, and an exact-DNS PUT to a key
other than the open epoch's each open a `replaced` epoch; an exact-DNS PUT of
the open epoch's key changes no epoch. A namespace registered before this
history existed gets epoch 1 when its stored controller repeats its
authenticated POST with exact DNS for that same key, rechecked under the
namespace row lock while the domain has no epoch at all. Inherited, failed
or skipped DNS, parent authorization and reverify never open, replace or
retire an epoch; reverify still updates the stored controller from exact DNS.
Deletion retires the open epoch, and sequences never reset. A controller key
outside the prime-order Ed25519 subgroup (small- or mixed-order) never opens an
epoch, even with exact DNS: the namespace write itself keeps its released
contract, but the identity tree has no root until a strict key is proven.

`POST /v1/namespaces/{domain}/rotate` takes exactly `{domain, operation,
from_seq, previous_did_key, new_did_key}` (`operation` is
`rotate_namespace_controller`, `domain` the canonical path domain,
`from_seq` a positive integer, two different strict did:keys). The previous
key signs the covering-v2 request in `Authorization` and the new key signs
the same payload in `X-AWEB-New-Key-Authorization`; there is no legacy form.
Exact DNS for `new_did_key` is looked up before the transaction. Under the
namespace row lock AWID rechecks the request timestamp and requires the
open epoch to be `from_seq` with key `previous_did_key`. It then stores the
new controller, retires that epoch and opens its `rotated` successor at the
same witness time, so registrations under the previous key stay valid.
Refusals use `detail.code`: 400 `invalid_shape`; 401 `invalid_signature` for
a missing, wrong-role or legacy proof or a stale timestamp; 409
`head_conflict` when the open epoch is not the named one (a replay or a stale
key); 503 `evidence_unavailable` when exact DNS does not prove the new key.
It shares the `namespace_rotate` rate-limit bucket with the PUT.

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

**Cross-registry consumption.** A receiving aweb service does not ask its home
registry to resolve an external sender held elsewhere. Its strict
external-address authority path selects a registry from the client-signed
sender address and `_awid.<domain>` DNS statement, then requires that registry's
exact namespace controller, address row, stable `did:aw`, current `did:key`,
identity log, and delivery origin to agree. No AWID request field or federation
wrapper may supply a registry URL. Absence of an AWID DNS record selects the
canonical public registry; malformed, multiple, timed-out, or failed discovery
does not fall back.

The receiving service may reuse one complete verified authority cohort for no
more than 60 seconds and then rereads DNS, namespace, address, key-or-log, and
origin. That is receiver cache policy, not an AWID revocation or freshness SLA.
A DNS controller or selected registry that continues serving an old but
cryptographically valid state can suppress an unseen transition indefinitely.
AWID supplies public evidence; the receiver's PostgreSQL checkpoints and
cohorts supply receiver-observed rollback/fork protection and shared
coordination.

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
plus one append to `did_aw_log`. It locks the mapping row before reading the
log head, so concurrent rotations and identity-tree registrations that select
this key serialize, and the appended entry's `created_at` is the post-lock
witness time of the new key epoch. There is no cascade to address rows:
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

Independent apps using the anonymous per-certificate status read require a
published record: a missing record is an authentication refusal on that path.
This publication prerequisite does not change the existing token/history,
server or CLI authority model; it never makes a registry row a substitute for
a valid controller signature. Custom BYOT signers must publish certificates
for independent status-based verification.

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
       Auth: none returns public teams only. A controller or unrevoked-member
             path signature, or the trusted same-operator service credential,
             also returns private teams visible to that authority.
       Response: { "teams": [{ "name": "backend",
                   "display_name": "Backend Team",
                   "team_did_key": "did:key:z6Mk...",
                   "visibility": "private", ... }] }

GET    /v1/namespaces/{domain}/teams/{name}
       Get team details.
       Auth: none for a public team. A private team requires its controller or
             unrevoked-member path signature, or the trusted same-operator
             service credential. Services call this to get the team public key
             and visibility metadata for certificate verification.
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
       Body: { "new_team_did_key": "did:key:z6Mk...",
               "resigned_records": {                      (optional)
                 "team_server":     { "record", "signature" },
                 "team_custodians": [{ "record", "signature" }],
                 "member_custody":  [{ "record", "signature" }],
                 "member_person":   [{ "record", "signature" }] } }
       Note: invalidates ALL existing certificates (they were
       signed by the old key). Members need new certificates.
       resigned_records carries every team-key-signed record of the team
       re-signed with the NEW key: unchanged apart from team_did_key and a
       newer issued_at, exactly one per stored record of each kind, and
       team_server whenever a server record is stored. AWID swaps the key
       and replaces the records in one transaction. A record that does not
       verify: 422. An incomplete, extra or changed set: 409
       resigned_records_incomplete with { missing, extra, changed } naming
       the keys per kind (team_server as a boolean, custodian_id,
       certificate_id), and nothing changes. The body is streamed against
       AWID_ROTATE_MAX_BODY_BYTES (default 4 MiB, never configurable lower):
       413 above it. Without resigned_records the rotation still succeeds,
       and verifiers refuse the old-key records until they are re-published.
       Contract: [principal-attestation.md](principal-attestation.md) §5.

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
               "certificate": "<required base64 team-signed certificate JSON>" }
       The canonical product term for the per-team routing key is member name;
       the current wire/schema field is still "alias" until the scheduled
       compatibility rename. Compatibility clients may send "lifetime"
       (legacy global/local storage); awid normalizes it to identity_scope
       before storage and never emits it in normal certificate responses.
       The certificate is signed externally by whoever holds the
       team controller private key (CLI for BYOD, hosted deployment for
       managed). awid records the issuance but does not sign. New
       registrations require this signed blob, with certificate_id, team and team key,
       member_did_key, optional member_did_aw and member_address, alias and
       identity scope matching the registration;
       a missing or mismatched blob is refused with 422. Historical records
       without a stored blob remain readable; this does not permit new
       blob-free registrations.
       member_address is the address selected for this specific team
       membership. A did:aw may have many awid addresses; the team
       certificate chooses which one is used when acting as this team
       member. If member_address is present, awid validates that it
       resolves to member_did_aw before recording the certificate.
       Response: { "registered": true, "certificate_id": "uuid" }

GET    /v1/namespaces/{domain}/teams/{name}/certificates
       List issued certificates (active and revoked).
       Auth: none for a public team; private-team read authority as above.
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

GET    /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/status
       Anonymous for public and private teams. Own certificate_status public-IP
       bucket: 60 reads per 60 seconds; trusted service reads are exempt.
       Response (exactly four fields):
         { "team_id": "backend:acme.com", "team_did_key": "did:key:z6Mk...",
           "status": "active" | "revoked", "revoked_at": null | "RFC3339" }
       Unknown/deleted team, unknown certificate, or certificate belonging to
       another team: identical 404 { "detail": "Certificate not found" }.
       No member identity, alias, addresses, enumeration, or history.
       The key is the CURRENT team key (did:key itself identifies the key).
       Active means revoked_at is null, not that authentication succeeded.
       Rotation can leave old-key records active; verifiers must reject their
       signatures against the current key. No previous key is returned.
       Cache per (team_id, certificate_id) for at most 60 seconds and fail closed
       on refresh errors. Existing private-read visibility remains unchanged.

GET    /v1/namespaces/{domain}/teams/{name}/members/{alias}
       Resolve an active team-member reference. The path segment is the
       member name; it is called alias in the current wire path for
       compatibility.
       Auth: none for a public team; private-team read authority as above.
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
       Auth: none for a public team; private-team read authority as above.
             Services cache this.
       Query params: since (timestamp, optional — for incremental sync)
       Response: { "revocations": [{ "certificate_id": "uuid",
                   "revoked_at": "..." }] }
       This is what services cache to reject removed members.

PUT    /v1/namespaces/{domain}/teams/{name}/server
       Publish the team's aweb.team-server/1 record.
       Auth: the record's own signature by the CURRENT team key; no request
       signature. Own team_server_publish public-IP bucket: 30 publishes per
       hour; trusted service publishes are exempt.
       Body: { "record": { "v": 1, "type": "aweb.team-server",
                           "team_id": "backend:acme.com",
                           "team_did_key": "did:key:z6Mk...",
                           "server_url": "https://coord.acme.com/api",
                           "issued_at": "2026-01-20T10:00:00Z" },
               "signature": "<unpadded standard base64 Ed25519>" }
       Signing bytes: "aweb.team-server/1\n" || canonical_json(record).
       Accepted only when the record has exactly these fields, names this
       team, carries the current team key and verifies under it, and its
       issued_at (UTC seconds: YYYY-MM-DDTHH:MM:SSZ in ASCII digits, naming a
       real calendar date) is at most five minutes ahead of AWID's clock.
       server_url is a canonical https origin with an optional path prefix
       (no trailing slash, userinfo, query or fragment), at most 2048 bytes;
       http only for loopback hosts, and localhost only in development. The
       request body is at most 8192 bytes (413 otherwise).
       A record must be newer than the stored one; resending the stored
       record answers 200 unchanged.
       Refusals: a record that does not verify against an existing team's
       current key (malformed, another team, another key, bad signature)
       answers exactly like an unknown or deleted team: 404
       { "detail": "Team server record not found" }, so publishing never
       reveals that a private team exists. A verified record can still be
       refused: 422 server_url_invalid | issued_at_in_future, 409 not_newer.
       Verifiers report the unverified cases with distinct codes
       (record_invalid | team_mismatch | team_server_key_mismatch |
       signature_invalid); AWID does not.
       Response: the stored { "record", "signature" }.
       A team key rotation leaves the stored record signed by the old key:
       consumers refuse it until the controller publishes a newer record
       signed by the new key, or the rotation carries it in resigned_records.

GET    /v1/namespaces/{domain}/teams/{name}/server
       Anonymous for public and private teams. Own team_server_get public-IP
       bucket: 120 reads per 60 seconds; trusted service reads are exempt.
       Response: { "record", "signature" } exactly as signed.
       Unknown or deleted team, and a team with no record: identical 404
       { "detail": "Team server record not found" }.
       Discloses the team's coordination server URL to anyone who knows the
       team id; it is not a credential, and every request to it is still
       authenticated. Consumers verify the record against the team's current
       key from the same registry, refuse a key mismatch, cache for at most
       60 seconds and fail closed. Conformance:
       [`vectors/team-server-record-v1.json`](vectors/team-server-record-v1.json).

PUT    /v1/namespaces/{domain}/teams/{name}/custodians/{custodian_id}
PUT    /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/custody
PUT    /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/person
       Publish an aweb.team-custodian/1, aweb.member-custody/1 or
       aweb.member-person/1 record.
       Auth: team controller, covering (v2) controller envelope only, with
       operation publish_team_custodian | publish_member_custody |
       publish_member_person and the path key as a claim.
       Body: { "record": {...}, "signature": "<unpadded base64url Ed25519>" }
       The record must verify under the CURRENT team key, name this team and
       the path key, and have issued_at at most five minutes ahead (422
       record_invalid | issued_at_in_future). Each publish holds the team row
       FOR SHARE and refuses with 409 team_key_changed if a rotation replaced
       the key, so publishes and rotations serialise. A byte-identical
       re-publish answers 200. Custodian and person records move forward only
       (409 record_not_newer). Custody needs an active certificate with that
       member_did_key and a custodian registered with at least one issuer key
       (409 custodian_not_registered) and is immutable apart from a re-sign
       after rotation (409 custody_immutable). Rate limits: 3000/hour per IP
       before authentication and 2500/hour per team after it; the trusted
       service token is exempt from both.

GET    /v1/namespaces/{domain}/teams/{name}/custodians/{custodian_id}
GET    /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/custody
GET    /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/person
       Anonymous for public and private teams; own attestation_record_get
       bucket, 60 reads per 60 seconds, trusted service reads exempt.
       Response: { "record", "signature" } exactly as stored. Unknown or
       deleted team, unknown key and absent record: identical 404
       { "detail": "Record not found" }. The custody and person reads
       disclose whether a certificate's key is held by a custodian and
       whether the controller declares its member one person.
       Contracts: [principal-attestation.md](principal-attestation.md),
       [member-person.md](member-person.md). Conformance:
       [`vectors/principal-attestation-v1.json`](vectors/principal-attestation-v1.json).

GET    /v1/namespaces/{domain}/teams/{name}/signed-records?limit=&cursor=
       Every team-key-signed record the team has stored, for a team-key
       rotation that must re-sign all of them: the aweb.team-server/1 record
       and the custodian, member-custody and member-person records, including
       those of revoked certificates.
       Auth: whatever the team's visibility, a path signature (the
       certificate-blob fetch scheme) by the team controller key, or the
       trusted service token. Members are not readers: the list would show
       them custodian records otherwise readable only by exact key. Anything
       else, an unknown or deleted team included, is the identical 404
       { "detail": "Team not found" }.
       Response: { "items": [{ "kind", "key", "record", "signature" }],
       "has_more", "next_cursor" }. kind is team_server, team_custodians,
       member_custody or member_person; key is null for team_server, else the
       custodian_id or certificate_id. Items are ordered by kind, then key, and
       pages are keyset cursors over that order (limit default 50, clamped to
       200; a malformed cursor is 400). Records are exactly as stored.
       Rate limit: own attestation_record_list bucket, 60 reads per 60
       seconds; trusted service reads exempt.
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

## Identity-tree registration and revocation

The identity tree's wire contract is [identity certificates](id-certificates.md);
this section states how AWID implements its registration and revocation
endpoints.

```
POST /v1/id-certificates/register   Register a parent-signed ID certificate
```

The body is exactly `{certificate, expected_head, invitation_id}`. The request
carries the covering controller envelope (`operation="register_id_certificate"`,
`domain` = the certificate's domain) signed by the subject did:aw's current
key; there is no legacy-envelope fallback. `X-AWID-ID-Chain` carries the full
chain, leaf byte-identical to the body certificate. Only did:aw subjects
register; a local agent's did:key certificate is carried, never registered.

Before its transaction, AWID checks the body, certificate shape and signature,
the envelope, and the chain's structure (links, R1, R3, cycles), and looks up
the controller key exact DNS proves for the domain. The
transaction then takes, in order: an advisory lock on the exact domain, the
domain's `dns_namespaces` row FOR SHARE, the subject's and parent's
`did_aw_mappings` rows FOR SHARE sorted by did:aw, and the subject's
`id_identities` row FOR UPDATE with its identity parent's FOR SHARE, in id
order. A registration and a revocation of its parent therefore serialize on
the parent's row as well as on the domain lock. Namespace rotation, reverify and delete hold
the namespace row FOR UPDATE, and did:aw rotation holds its mapping row FOR
UPDATE, so each serializes with registration. After the last lock wait it
resolves an exact existing receipt (same digest and invitation) before any
fresh-issuance check, then checks invitation reuse, the subject's fixed kind
and domain, revocation and head CAS, current root authority (the stored
controller, the open epoch's key and that DNS key agree; the skip-DNS bypass
proves nothing), the parent (the root key for a namespace parent; a
registered, unrevoked, same-domain parent's current key for an identity
parent) and that the presented ancestors are the
registered current heads. For an identity parent it then has the shared chain
verifier (`awid.id_certificates.verify_id_chain`) judge the parent's whole
current chain against a status snapshot read inside this transaction, with
the DNS key observed before it: a revoked or replaced ancestor, an agent edge
whose parent is no longer valid, or a stale key refuses with the verifier's
reason (`revoked`, `root_replaced`, ...), and unavailable evidence (for
example a proof over the byte limit) refuses `evidence_unavailable` (503). A
human invitee keeps its standing after its inviter's later revocation, as the
contract's historical human-parent rule says. It records `registered_at` from the post-lock clock,
strictly after the latest identity-tree event in the domain and the selected
key epochs, with the exact `issuer_key_seq`.

A success returns exactly `{certificate_id, registered_at}`. Refusals use
`detail.code`: 400 for shape and encoding (`invalid_shape`, `invalid_json`,
`invalid_encoding`, `invalid_signature`, `bundle_too_large`,
`noncanonical_json`, `depth_exceeded`), 401 for the envelope, 403
`subject_mismatch`, 409 `head_conflict` and `invitation_conflict`, and 422 for
the tree's refusals (`domain_mismatch`, `human_issuer_is_agent`, `cycle`,
`duplicate_id`, `missing_parent`, `identity_kind_immutable`, `subject_revoked`,
`unregistered_parent`, `parent_revoked`, `issuer_key_not_current`,
`superseded_certificate`, `root_replaced`), and 503 `evidence_unavailable` when the domain has
no current root authority.

Registration is rate limited in the `id_certificate_register` bucket: 300
requests per hour per client IP. Every request does signature and database
work before it can be refused, so an anonymous caller must not be able to
drive it unbounded; a human or global-agent enrollment is rare, so the bucket
does not limit ordinary use. The only exemption is the deployment's
configured `AWID_SERVICE_TOKEN` presented in `X-AWID-Service-Token` (the
hosted service registering on behalf of its users). A missing or wrong token,
or any token while none is configured, counts against the caller's bucket.
The exemption is rate-limit only: it never replaces the subject's key proof
or the parent's signature.

```
POST /v1/id-certificates/revoke     Revoke a registered ID
```

The body is exactly `{domain, id, expected_head, effective_from}`: `id` is a
registered did:aw, `expected_head` its current certificate digest, and
`effective_from` either null or a fixed-microsecond UTC time
(`YYYY-MM-DDTHH:MM:SS.ffffffZ`). The covering controller envelope
(`operation="revoke_id_certificate"`, `domain` = the request's domain) is
signed by one of the allowed revokers; there is no legacy-envelope fallback.
The transaction takes registration's locks in the same order, reading the
subject's current head under the domain lock to find its parent, so it
serializes with registration, re-parenting and rotation in the domain.

After the last lock wait, a registered ID with no current head refuses
`evidence_unavailable`. It then resolves the signer, the root first:

- the namespace root, by the current root key (the stored controller, the
  open epoch's key and the exact DNS key looked up before the transaction
  agree), even when that key is also the subject's or the parent's current
  key;
- the ID itself, by its did:aw's current key;
- its current parent, by the parent did:aw's current key, but only while the
  shared chain verifier finds the parent's whole current chain valid in a
  snapshot read inside this transaction: an invalid parent (revoked itself,
  or under a revoked or replaced ancestor) is `revocation_forbidden`, and
  unavailable evidence is `evidence_unavailable`;
- any other signer is `revocation_forbidden`, unless the domain has no
  current root authority: then AWID cannot tell whether the signer is the
  root, and it refuses `evidence_unavailable`.

A null `effective_from` means the post-lock serialization time, which also
becomes `revoked_at`: strictly after the domain's latest identity-tree event
and the revoking ID's or parent's key epoch. Only the root names a cutoff, and never a
future one. A repeat writes nothing and returns the stored times, after the
same head and actor checks. The root may move an existing cutoff earlier,
which changes only `effective_from`; `revoked_at` keeps the original
witness time. A later cutoff is refused.

A success returns exactly `{revoked_at, effective_from}`. Refusals use
`detail.code`: 400 `invalid_shape` and `invalid_json`, 401 for the envelope,
403 `revocation_forbidden` and `backdate_forbidden`, 404 `unknown_id` (no
registered ID by that id), 409 `head_conflict`, 422 `domain_mismatch` and
`invalid_cutoff`, and 503 `evidence_unavailable`. Revocation is rate limited
in the `id_certificate_revoke` bucket, 300 requests per hour per client IP,
with the same `AWID_SERVICE_TOKEN`-only exemption and rationale as
registration.

```
POST /v1/id-certificates/status     Snapshot of exact registered IDs and namespace epochs
```

The body is exactly `{v: 1, domain, ids}` with 0–8 distinct canonical did:aw
strings; any other field (a prefix, a search) is `invalid_shape`. An
authenticated caller signs the covering-v2 request
(`operation="read_id_certificate_status"`) with a strict-profile key. Supplied
but invalid proof, or the legacy form, is 401, never anonymous. Every request
is charged to its source IP's `id_certificate_status` bucket, and a verified
caller also to its key's (keys cost nothing to mint, so a key bucket alone is
no limit). Each allows 60 requests per minute, with no service exemption, and
both are charged before the DNS lookup and any database read. The domain is
canonicalized (lowercase, no trailing dot) and must be a valid name.

The response is one coherent snapshot, read in a single read-only REPEATABLE
READ transaction: the domain's complete epoch history with `continuity`, then
each requested registered ID in request order followed by its proof closure
(every same-domain identity named as a parent by any revision of an included
identity, deduplicated by a visited set), each with its full certificate
revisions, DID-log key history and revocation; `missing` lists requested IDs
not registered in this domain. `observed_at` never precedes the snapshot's
latest event. No invitation, membership, email or account data appears. While
the stored controller, the open epoch and exact DNS disagree, or as soon as
the response being built would exceed 131072 bytes, the endpoint answers 503
`evidence_unavailable` with no partial evidence.

### Cached status client

A status response is authority evidence only when the production cached
client obtained it. `CachedRegistryClient.id_chain_evidence(bundle, subject,
*, domain)` (`awid/src/awid/registry.py`) returns the verifier's
`IDChainEvidence` and never raises on a fetch failure;
`RegistryClient.fetch_id_certificate_status(domain, request)` is the raw POST,
which raises.

- `domain` is always supplied by the caller. A chainless local subject, or a
  request the verifier would refuse before reading evidence (another domain,
  an oversized bundle), does no DNS or HTTP work and gets evidence without an
  age.
- One Redis entry per exact status request holds the status response together
  with the namespace authority (`domain`, `dns_name`, `inherited`,
  `controller_key`) from the client's `DomainVerifier`, both fetched in one
  attempt. The entry's age is measured on this client's clock from when that
  attempt began, never from the body's `observed_at`, and it survives
  restarts.
- Evidence aged 60 seconds or less is served with no DNS, routing or HTTP
  work. Older evidence waits for one refresh shared by every concurrent caller
  of that request; a cancelled caller does not cancel it. DNS, routing and HTTP
  share one `timeout_seconds` bound.
- Any successful JSON object answer replaces the entry, including a missing,
  revoked, replaced or contradictory one, and the verifier judges it. A
  successful answer that is not a JSON object within the response bound
  removes the entry, so no older tree outlives it.
- A failed attempt (timeout, transport error, DNS failure, any refusal
  including 429) never touches the entry. The caller gets the last-known-good
  evidence with its true age and `refresh_failed`, or, with none, evidence
  without an age. The verifier allows the outage grace through 900 seconds and
  reports `status_expired` after it.
- A failed attempt stands for every refresh of its domain for the next 60
  seconds inclusive, in process memory only, so a stalled registry costs one
  timeout per window. During it callers get exactly the failed-refresh answer
  above, with no network attempt; it never changes an age or extends the
  grace. A successful answer ends it. Each domain's entries and cooldown are
  independent of every other domain's.

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
8. `008_team_server_records.sql` adds the team-key-signed team-server record.
9. `009_principal_attestation_records.sql` adds the team-key-signed team
   custodian, member custody and member person records, deleted with their
   team or certificate.
10. `010_id_certificates.sql` adds the identity tree's registered identities
    with their revocation, every registered ID-certificate revision, and the
    namespace controller epochs ([identity certificates](id-certificates.md)).

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
- `team_server_records`
- `team_custodians`
- `member_custody`
- `member_person`
- `id_identities`
- `id_certificates`
- `id_namespace_epochs`
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

# Required when this AWID serves aweb; set the same >=32-byte secret on both.
# Generate, for example, with: openssl rand -hex 32
AWID_SERVICE_TOKEN=
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
- Require matching team-signed cert blobs for new registrations and publish
  them for cross-machine fetch and recovery; historical blob-free records
  remain readable. Registry row existence is not authorization.
- Serve cert listings for optional dashboard / audit / discovery

**Does not:**
- Hold private keys (no escrow, no custody keys)
- Store aweb receiver-wide message receipts, contact identity bindings, or
  receiver authority cohorts; those are recipient-service PostgreSQL state
- Promise that a receiver will observe an address/key/registry transition within
  60 seconds when an authoritative source suppresses it
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

## Controller HTTP mutation envelopes

Header-authenticated controller mutations accept the additive covering wire in
[AWID controller requests](awid-controller-requests.md), with explicit protocol
type and configured audience, method, external target and exact request-body
hash. Legacy acceptance remains measured until the operator's separate cutoff.
New certificate records require a matching complete team-signed blob;
historical records remain readable. Identity custody and controller authority
remain separate, and existing signed body-artifact protocols are unchanged.
