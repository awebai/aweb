# awid — Source of Truth

Status: **canonical normative contract for shipped AWID identity, certificate,
and trust behavior, plus the explicitly marked approved parent-delegation target
that must land before inherited children can use strict federation**.

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
6. **Approved target — parent delegation is portable authority, not a registry
   verdict.** A parent controller may authorize a child namespace with a distinct
   controller. For same-registry mutation the registry verifies that
   authorization at write time. For cross-registry verification the registry
   must also publish the exact parent-signed delegation assertion and its
   append-only history. `verification_status`, row existence, and the
   registry's own signature or attestation are never substitutes for the
   controller proof.

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

These request-authentication signatures are admission evidence, not durable
delegation credentials. In particular, the timestamp-bounded
`authorize_subdomain_registration` and `authorize_subdomain_rotation` headers
must not be replayed later as public proof. A parent-authorized namespace write
also carries the versioned durable delegation assertion defined below; AWID
verifies and persists that assertion atomically with the namespace mutation.

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

Public identity and namespace read endpoints (`GET /v1/namespaces/{domain}`,
`GET /v1/did/{did_aw}/key`, etc.) are rate-limited and do not require
signatures. Team reads follow team visibility: public teams are anonymous;
private-team metadata, enumeration, certificate history, member lookup, and
revocations require a controller or unrevoked-member path signature, or the
trusted same-operator service credential described below. Identity-private
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
exempts the `did_key`, `did_addresses`, and `revocation_list` read buckets from
public-IP rate limits. It never authorizes a write, and must not be shared with
clients or sent to a discovered external registry. Missing credentials use the
normal visibility and public-IP rules. A wrong presented credential grants no
private read access, uses those limits, and emits the stable
`awid_service_credential_rejected` telemetry event without logging the secret.

---

## Namespaces

DNS-rooted organizational domains. `acme.com`, `juanre.aweb.ai`. A namespace
is controlled either directly by the controller in its exact `_awid.<domain>`
record or by a parent-authorized child registration rooted at the nearest
inherited `_awid` record. The approved target below makes that existing child
relationship portable to a strict external verifier.
The exact-match reserved namespace `local` is also allowed for local
development/bootstrap without DNS verification; after creation it behaves
like any other namespace.

```
POST   /v1/namespaces                  Create (controller auth)
GET    /v1/namespaces/{domain}          Read (public)
PUT    /v1/namespaces/{domain}          Rotate controller key
DELETE /v1/namespaces/{domain}          Delete (controller auth)
```

### Parent-delegated namespace authority

Status: **approved target contract; implementation is a release blocker for
strict federation of parent-delegated namespaces**.

The April parent-authorization model remains canonical: a parent namespace may
create a child with a distinct controller, and DNS lookup may inherit the
nearest ancestor `_awid` record. Exact per-child DNS is optional and must not be
required by a hosted provider. To make that relationship independently
verifiable, every active inherited child exposes a durable delegation head and
append-only log.

The canonical `awid.namespace-delegation.v1` payload contains exactly:

```json
{
  "version": "awid.namespace-delegation.v1",
  "operation": "delegate",
  "parent_domain": "aweb.ai",
  "child_domain": "juanre.aweb.ai",
  "child_controller_did": "did:key:z...",
  "sequence": 1,
  "previous_delegation_hash": null
}
```

Canonical JSON is UTF-8 with lexicographically sorted object keys, compact
separators, no ASCII escaping, and no fields beyond those listed above: the same
`canonical_json_bytes` rule used by AWID signed writes. Both domains use
`canonical_protocol_domain`: lowercase ASCII, no trailing dot, and valid DNS
labels. `child_controller_did` is a valid Ed25519 `did:key`; `sequence` is a
positive JSON integer. `previous_delegation_hash` is `null` only at sequence
one and is the prior entry's hash thereafter. The entry hash is `sha256:` plus
the lowercase hex SHA-256 digest of the canonical payload.

The assertion carries one or more entries of `{controller_did, signature}`.
Each signature is unpadded RFC 4648 standard-base64 Ed25519 over the exact
canonical payload bytes. A `delegate` or `rotate` entry requires a signature matching the current
controller established for `parent_domain` by DNS or by the immediately
preceding verified delegation link. A `revoke` entry requires the current
`child_controller_did` signature. Multiple parent signatures over one active
`delegate` or `rotate` payload are allowed only to bridge a parent-controller
rotation; they do not create several parents or weaken the exact-match rule.
Signature attachments are append-only so a historical entry remains
reproducible.

Rules:

- `parent_domain` is the immediate namespace authority that issued the link;
  `child_domain` must be its strict DNS descendant. A deeper target carries an
  ordered chain of links from the DNS-selected ancestor to the exact target:
  the first `parent_domain` equals the DNS authority domain, every later
  `parent_domain` equals the preceding `child_domain`, and the final
  `child_domain` equals the requested namespace. Missing, extra, reordered, or
  disconnected links fail closed.
- `parent_domain` is immutable for the life of a child log, including backfill
  and every successor. It must be one of the registrable-domain-bounded
  ancestor candidates used by AWID DNS discovery, and the submitted hierarchy
  must be rootable at admission from that candidate set. Reparenting is not a
  v1 operation: if a newly nearer `_awid` record makes the stored chain
  unreachable from the verifier's DNS root, verification fails closed. The
  operator may use exact child DNS; changing a delegated child's parent requires
  a future versioned protocol rather than editing, splicing, or restarting the
  v1 history.
- `operation` is exactly `delegate`, `rotate`, or `revoke`.
  `sequence` starts at one and increases by exactly one for every child
  controller change, revocation, or post-revocation name reuse. A successor binds the
  exact previous hash.
  Same-sequence/different-hash, lower-sequence, gaps that cannot be filled from
  the complete log, and forks fail closed.
- `delegate` creates the first active binding. `rotate` changes the child
  controller. Both also require proof of possession of the named child
  controller through the normal namespace write authentication. `revoke`
  preserves the last controller in the payload, is signed by that current
  child controller rather than silently changing April deletion authority,
  makes the child inactive, and remains publicly readable after namespace
  deletion. Reuse under inherited authority requires a parent-signed successor
  `delegate` that extends the tombstone's sequence and hash; the link never
  starts a second history. Exact DNS may independently re-register the name
  while the revoked delegation log remains dormant, but returning to inherited
  authority still requires that successor.
- The link state machine is exact: absent → `delegate` at sequence one →
  active; active → `rotate` → active; active → `revoke` → inactive; inactive →
  `delegate` at the next sequence → active. Every other transition fails
  closed. A `revoke` immediately extends the active head, names the same
  controller as its predecessor and current namespace row, and is signed by
  that controller.
- AWID atomically persists the verified assertion/log entry with the matching
  namespace create, controller rotation, or deletion. Under inherited
  authority, the namespace row and active delegation head may never disagree.
- Public namespace reads expose the active head and the ordered chain needed to
  reach the DNS-selected ancestor. A dedicated complete-log read remains
  available for checkpoint gaps, deleted children, and audit. Registry-generated
  or unsigned delegation-shaped fields have no authority.
- A receiver persists the highest verified `(sequence, hash)` for every
  parent/child link in PostgreSQL. A new head must equal or extend that
  checkpoint before it can authorize delivery. Process memory, Redis, TOFU,
  and the receiver's home registry cannot replace this checkpoint.
- A registry can suppress an unseen valid successor or revocation by serving
  an older still-valid signed history. This is the same named source-suppression
  residual accepted for other registry-served signed state; the protocol makes
  no global freshness claim. It may not roll back a transition the receiver has
  already checkpointed.
- Parent-controller rotation uses the fenced rollover API below. It blocks
  immediate-child mutations, adds the new parent's signature to every active
  immediate-child head, and proves the complete frozen set before the parent
  controller changes. A direct parent then completes its normal DNS plus
  registry-row rotation; a delegated parent completes its own parent-signed
  `rotate` entry and registry-row update. Nested parents do not change DNS.
  Historical signatures remain public evidence; an old signature alone no
  longer authorizes a child because verification still requires a signature
  matching the controller selected by current DNS or the preceding delegation
  link.
- Registry migration does not change the delegation proof. The operator copies
  the exact namespace, address, DID, identity-log, delivery-origin, delegation,
  and tombstone state to the destination, reads it back there, and then changes
  DNS. The affected subtree uses one committed cutover generation: mutations to
  every included namespace, address, DID/log, route, and delegation record are
  fenced during the final snapshot/readback, and DNS cannot change until the
  destination proves that complete generation. Old-DNS readers use the old
  registry and new-DNS readers use the new one; both serve the same cutover
  generation and signed delegation history until the overlap ends. A registry
  URL supplied by a message or wrapper is never consulted.
- Existing parent-authorized children are backfilled with a sequence-one
  `delegate` assertion for their current controller before strict external
  verification is enabled for them. Backfill changes neither their controller,
  addresses, teams, nor DNS.
- A parent namespace with active delegated direct children cannot be deleted.
  Every direct child log must first reach a child-signed revoked head so
  deletion cannot orphan an active delegation tree. Detaching a live child from
  its immutable v1 parent without deleting it is not a v1 operation.

For a fresh receiver, each active link head must have at least one valid
signature from the parent controller established by live DNS or the preceding
active link; that current signature attests the head and the history hash it
commits. Old entries are not required to carry today's parent signature. For a
receiver with a link checkpoint, the registry must supply a contiguous
canonical hash suffix from the exact checkpoint to the current head; the
current established parent must sign the active head, and a revoked head never
authorizes delivery. Missing checkpoints, forks, or non-contiguous suffixes
fail closed.

#### Target wire contract

The wire assertion is exactly:

```json
{
  "payload": {"version": "awid.namespace-delegation.v1", "...": "..."},
  "entry_hash": "sha256:...",
  "signatures": [
    {"controller_did": "did:key:z...", "signature": "base64..."}
  ]
}
```

`payload` contains exactly the canonical fields above. `entry_hash` is derived,
not part of the signed payload. Signature entries are sorted by
`controller_did`; duplicate controller entries and unknown fields fail closed.
The following target surfaces are normative rather than left to a later
OpenAPI decision:

- Inherited-child `POST /v1/namespaces`, `PUT /v1/namespaces/{domain}`, and
  `DELETE /v1/namespaces/{domain}` carry `delegation_assertion` in their JSON
  body. Create and rotate retain the current new-child-key proof; delete retains
  current child-controller authentication and carries a child-signed `revoke`
  assertion. A directly DNS-controlled namespace with no delegation history
  omits the field.
- `POST /v1/namespaces/{domain}/delegation/backfill` attaches only a
  sequence-one `delegate` to an existing active inherited child with no
  delegation history. It requires both current child-key possession and current
  parent authorization. It cannot replace a history or change a namespace row.
- `GET /v1/namespaces/{domain}` adds `delegation_chain`, containing the stored
  chain whenever one exists and otherwise an empty array. The registry does not
  infer authority mode from its own DNS view. The external verifier chooses or
  ignores the returned chain using its live exact-versus-inherited DNS result.
  Stored assertions are ordered from their stored genesis/root link to the
  exact target. The verifier requires the first parent to equal its live DNS
  authority; an unreachable stored chain fails closed. The endpoint remains
  public and returns only active namespaces.
- `GET /v1/namespaces/{domain}/delegation-log?after_sequence=N&limit=L` (then
  `?cursor=C` for continuation) is
  public for active and deleted children. It returns ascending contiguous
  entries after `N`, `has_more`, `next_sequence`, `next_cursor`,
  `head_sequence`, and `head_hash`; the server-enforced page maximum is 100. `N=0` reads from
  genesis. The first page fixes a snapshot head, and every continuation cursor
  is opaque and bound to that exact head; continuations use `next_cursor` and
  do not repeat `after_sequence`. The final returned entry must equal the
  snapshot head and, for an active log, the head carried by the namespace
  chain. A deleted log has no namespace GET and instead ends at the signed
  tombstone identified by the log response's snapshot head. An empty page
  is valid only when `N == head_sequence` and `has_more` is false; otherwise an
  empty, repeated, skipped, reordered, changed-head, or non-monotonic page is a
  truncation/protocol failure. If the live head changes during collection, the
  verifier discards the partial result and refetches the complete authority
  cohort. A direct namespace with no delegation history returns 404.
- A retry is idempotent when canonical payload bytes and entry hash match and
  every submitted valid signature is present unchanged in the stored
  append-only signature set; it returns the stored superset. The same sequence
  with different payload/hash, the same controller with different signature
  bytes, or any attempt to remove a stored signature returns 409 without
  mutation. The rollover API is the only route that may append a new-controller
  signature without changing sequence or hash. AWID persists the exact
  canonical payload bytes and signatures it verified; reconstructing an
equivalent object later is not sufficient readback evidence.

[`vectors/namespace-delegation-v1.json`](vectors/namespace-delegation-v1.json)
is the normative known-seed canonical-bytes, hash, DID, and signature vector.
Implementations and generated clients must reproduce it byte for byte.

Authority mode is selected only by the verifier's DNS result. A delegated child
may later acquire exact DNS; its stored delegation history remains public but
is dormant while exact DNS controls it. Direct controller rotation may then
omit `delegation_assertion` and change the namespace row without rewriting that
dormant head. Before exact DNS is removed, a parent-authorized `PUT` must append
a valid successor whose controller matches the current row and read it back.
Deleting a namespace that has any delegation history always appends the current
child-signed `revoke`, even while exact DNS is active, so removing exact DNS
cannot resurrect an old active head.

Parent-controller rotation uses a resumable fence:

1. `POST /v1/namespaces/{parent_domain}/controller-rollovers` is authorized by
   the current parent and proves possession of `new_controller_did`. It creates
   one pending rollover, blocks registration/rotation/deletion/reuse of its
   immediate children with a retryable 409, and freezes an immutable snapshot
   of every non-revoked immediate-child head. It refuses to start if an active
   inherited child lacks a delegation head. The response contains counts and a
   rollover id, not an unbounded child list.
2. `GET /v1/namespaces/{parent_domain}/controller-rollovers/{rollover_id}/children`
   pages that frozen snapshot with an opaque cursor and a server maximum of 100
   heads. Every page returns exact child domains, head hashes, and canonical
   payloads; it is stable for the life of the rollover.
3. `PUT /v1/namespaces/{parent_domain}/controller-rollovers/{rollover_id}/signatures`
   accepts at most 100 corresponding new-parent signatures. Each bounded batch
   is atomic and idempotent. Missing or invalid items roll back that batch;
   duplicate valid submissions return the stored result. AWID marks the
   rollover ready only after every frozen head is covered and a complete stored
   readback verifies the expected new signature.
4. The normal parent controller rotation must name the ready `rollover_id`. For
   a direct parent the operator first publishes the new exact DNS controller;
   the normal `PUT /v1/namespaces/{domain}` then reverifies that DNS and new-key
   proof, atomically rotates the registry row, and marks the rollover in overlap.
   For a delegated parent the same `PUT` instead carries its valid
   parent-of-parent-signed `rotate` assertion and atomically updates its own
   delegation head plus registry row; it changes no DNS. Immediate-child
   mutations remain fenced for at least the previous DNS TTL for a direct
   parent or the 60-second strict-authority reuse bound for a delegated parent,
   so no new child appears with only the new signature while a valid old
   authority view remains.
5. `POST /v1/namespaces/{parent_domain}/controller-rollovers/{rollover_id}/complete`
   is authorized by the new parent and clears the fence only after that overlap.
   `GET` on the rollover resource exposes resumable state. `DELETE` cancels it
   under the still-current parent authority only before controller cutover.

Key-loss recovery retains the April authority model. If the current parent key
is unavailable, rollover preparation may instead prove the replacement through
live exact DNS for a direct parent or through the parent's own valid
grandparent-signed successor `rotate` assertion for a delegated parent; new-key
possession is still required. The recovery authority and prepared assertion are
stored with the fence and consumed by the normal parent row/delegation update.
This path may have a fail-closed availability window while DNS changes, but it
does not strand the parent or silently grant the registry recovery authority.

If exact-DNS key loss prevents AWID from independently establishing the prior
TTL, automatic overlap release remains fail closed. The sole v1 override is an
internal DB-credential/Typer capability, never a public controller-authority
route. It requires live exact DNS selecting this registry's configured canonical
public origin, fresh new-controller proof over the exact canonical risk payload,
an explicit assumed prior TTL/change time, operator identity, nonempty reason,
and literal risk acceptance. AWID stores immutable canonical bytes, signature,
DNS evidence, `complete_after`, actor/reason hashes, and a loud warning that old
authority readers may fail if the assumption is short. Exact retries return that
stored readback even after admission freshness expires; conflicting retries fail.
The override releases only the overlap fence and never authorizes controller
change or child signatures.

Registry migration is likewise an internal DB-operator protocol. Source prepare
requires canonical expected source and destination origins plus a second
authoritative DNS observation inside the locked snapshot transaction. The
manifest copies exact subtree state and the reachable ancestor delegation suffix
under one source generation. Destination import must match its configured public
origin and preflight every deterministic primary key. Missing rows are inserted;
semantically exact local rows may be reused; imported rows may be reused only
after their owner is no longer cancelable. The closed v1 semantic projection
excludes exactly `state_source_registry_id`, `state_cutover_id`, and
`state_generation`. Reused provenance is never rewritten. Actual-table readback
binds source and semantic manifests, per-kind inserted/reused counts, and owner
provenance.

DNS eligibility and overlap use strict non-self-referential receipts. They bind
both registry ids, cutover id, source generation, manifests, expected destination
origin, DNS name/controller/origin, authority-answer digest, observations, old
authoritative TTL, skew allowance, and shared `complete_after`. Destination and
source each perform a fresh independent authoritative DNS observation under the
cutover lock before release. Destination releases first and emits its completion
receipt; source consumes it and releases second. Exact completed retries use
stored receipts without rerunning historical DNS. Cancel removes only exact
`inserted` provenance; reused rows and their owners survive.

Public reads continue during a rollover. Signature attachment does not change
the entry hash or delegation sequence. These endpoint shapes, exact bytes,
pagination rules, and fence semantics are part of the v1 contract; live
OpenAPI and generated clients must match them before the target is called
implemented.

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

**Cross-registry consumption target.** A receiving aweb service does not ask
its home registry to resolve an external sender held elsewhere. Its strict
external-address authority path selects a registry from the client-signed
sender address and `_awid.<domain>` DNS statement. An exact DNS controller may
authorize the namespace directly. When DNS authority is inherited and the
target has a distinct controller, the receiver requires the complete verified
parent-delegation chain above. It then requires that final controller, the exact
namespace and address rows, stable `did:aw`, current `did:key`, identity log,
and delivery origin to agree. No AWID request field or federation wrapper may
supply a registry URL. Absence of an AWID DNS record selects the canonical
public registry; malformed, multiple, timed-out, or failed discovery does not
fall back. `verification_status` without valid controller evidence never
authorizes delivery.

Until the approved delegation contract is implemented, the shipped strict
adapter continues to fail closed when inherited DNS names a parent controller
that differs from the exact child namespace controller. A registry status bit
or unsigned delegation-shaped response must not bridge that gap.

The receiving service may reuse one complete verified authority cohort for no
more than 60 seconds and then rereads DNS, namespace, address, key-or-log, and
origin. That is receiver cache policy, not an AWID revocation or freshness SLA.
A successful verification compare-and-swaps every advanced delegation-link
checkpoint, the DID checkpoint, and the complete reusable authority cohort in
one PostgreSQL transaction before any message effect. A conflict or persistence
failure rolls back all of them and fails delivery; no cohort may become reusable
without all rollback state committed beside it.
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
8. `008_namespace_delegation.sql` atomically adds the complete portable
   namespace-delegation contract: append-only history/signatures, replay-stable
   snapshot pages, controller-rollover and recovery fences, source-preserving
   registry-cutover generations/receipts, and exact-provenance cleanup guards.

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
- `namespace_delegation_heads`
- `namespace_delegation_entries`
- `namespace_delegation_signatures`
- `namespace_delegation_read_snapshots`
- `namespace_delegation_read_pages`
- `namespace_controller_rollovers`
- `namespace_controller_rollover_children`
- `namespace_controller_rollover_risk_acceptances`
- `registry_state`
- `registry_migration_cutovers`
- `registry_migration_items`
- `namespace_controller_rollover_read_pages`
- `namespace_controller_rollover_first_pages`
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

# Canonical public origin; required by migration import and risk override.
AWID_PUBLIC_ORIGIN=https://api.awid.ai
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
