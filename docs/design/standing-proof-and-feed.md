# Standing proofs and the AWID invalidation feed

Status: design for review, aweb-aeal. OSS defines the protocol. E5 is its
first deployment. The current service continues to use its released contract
and its separately assigned security fixes.

Juan decided these four requirements on **2026-11-28**.

- Ordinary standing is portable across verifiers for its exact binding and
  lasts at most **30 minutes**. The statement carries no audience or operation.
- Each registry publishes one mandatory public signed feed of random
  invalidation handles. Its aggregate count and timing are public and unpadded.
- A verifier fails closed for new effects at **30 seconds** without a fresh
  applied authenticated feed point for the issuer. An effect already admitted
  may finish.
- One rule applies to subscription and on-demand fetch. A verifier sets no
  shorter local maximum statement age.

The remaining wire and implementation details are design for review.

## 1. Authority and scope

A controller-signed certificate establishes the credential. The authoritative
registry signs evidence that the credential's dependencies stood at a committed
cut. A holder-signed request proves possession and binds the destination,
operation and content. The serving application applies its own policy. A
standing statement confers no membership, delegation, routing authority or
permission to read private data. The identity, team and custody authorities
remain those in the [trust model](../trust-model.md).

For each issuer an effect relies on, the verifier's applied authenticated
feed point must cover a cut at least as recent as the presented evidence.

The request's authority decision uses local state. No cache miss, first contact,
grant, app call, stream continuation or federation handler falls back to a
registry lookup. Clients obtain positive evidence before submitting requests.
Feed and discovery workers can do network I/O. The E5 runtime and pilot
route owners inventory the routes E5 will enable. If E5 needs an AWID mutation
through an existing aweb proxy, the affected route must move to an authorised
client/control-plane journey or a separately authorised durable job with
documented settlement before E5 enables it. Proxy routes used only by the
current service belong to that service's later retirement inventory.

## 2. Statements

All statement, feed-barrier and snapshot signatures have distinct versioned
purpose labels. The proposed byte encoding is Ed25519 over the ASCII purpose
label followed by a newline and the UTF-8
[JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
payload. Carry payload and signature as unpadded base64url. Pin the issuer and
its key for the exact scope and signing purpose independently of the proof.
Reject unknown versions, duplicate fields, overlong lists and malformed
canonical representations. Encode cursors and timestamps as canonical decimal
strings with an explicit unit and range. Freeze these bytes and their refusal
rules in shared vectors before the SDK contract lands.

An ordinary standing payload signs the registry identity and key ID, stream
era, committed change position, observation time, exclusive expiry, assertion
kind, exact facts and the complete set of dependency-version handles. It carries
no service audience or operation. A statement for another credential, kind or
scope cannot satisfy the requested check.

| Asserted fact | Exact binding and relevant invalidations |
|---|---|
| Team membership | Canonical team ID, certificate ID and digest, member signing key and registered subject when present. Depends on that membership and the team incarnation and key version. |
| Global identity | Stable DID, current signing key and required registered chain. Depends on the leaf, relevant ancestors and the namespace epoch. The issuer can invalidate an ancestor or epoch once for all dependent proofs. |
| Address or route | Exact address assignment or signed routing record, owner, destination and relevant version. Include it only where the operation relies on that fact. |
| Service delegation | The owning service checks the exact grant, subject, session key, expiry and scope. A registry statement covers only the resident's registry dependencies. The service supplies its own facts and invalidations if a separate verifier is authorised to honour them. |

For an enrolled global member, the issuer of the membership and the authority
over its identity can differ. Require both proofs when both facts are used and
match their bindings. A local team identity uses membership evidence for that
team. A genuinely local identity-only lane stays scoped to its existing exact
local admission. Omitting a global identity claim cannot select the local
lane for an enrolled identity. Display aliases are never authoritative keys.
App installation, manifest and scopes are owned by aweb and checked
independently of the member's standing.

A proof-bearing request signs its audience, operation, target, body and the
attached evidence set. Verify the holder signature separately from the issuer's
statement. Every route accepting statements refuses the compact v1 and existing
identity-only envelopes. The E5 inventory must migrate global-identity mail
from today's identity-only envelope to a request-bound envelope. It keeps
the identity signing key as the holder and binds the evidence and request
fields above. Existing per-purpose replay, replay receipt and recipient-binding
rules still apply. Keep private positive issuance at the existing authorised
boundary. One issuer must not grant read access on another issuer's behalf. A
grant worker needs scoped authorisation to obtain its resident's evidence
without getting the resident's signing key. The grant journey must prove that
an expired or revoked grant cannot use a still-valid resident statement and
that evidence issuance confers no access to the private roster.

### Issuance

Read positive dependencies and the committed change cursor from one
authoritative snapshot. Its observation time is no later than acquisition of
that snapshot. Do not extend it at signing completion, retry or cache reuse.
An authenticated primary cut containing a revocation cannot issue positive
evidence for the revoked version. An earlier read that finishes signing later
keeps its original cut and deadline. Routine evidence can be reused within its
signed binding and lifetime. An applicable credential deadline independently
limits use. Current-evidence issuance always takes a current authoritative cut.

## 3. Exact-request evidence for authority creation

A member creating authority needs distinct current evidence. Start with grant
mint, connect, app install and app-request approval when admitted as a member.
Review the route inventory before declaring it complete. Controller acts
submitted to AWID and service-owned authority lanes keep their own current
checks.

The holder signs the exact method, operation, service audience, team, target
and digest of the final effect-bearing inputs. The digest omits the returned
evidence and outer signature. The registry checks the request and the relevant
standing at its current committed cut and signs those bindings, the required
dependencies, an exclusive expiry and a one-use ID. An ordinary statement
cannot satisfy this proof type. Stage an app manifest before requesting current
evidence for its exact digest and scopes. Never enable unknown, unreadable or
expired authority on a retry.

At the destination, check the bindings, expiry and applied prefix after the
last relevant wait. Consume the ID with the effect in one transaction. A
retry of the same request may read its recorded receipt. A different digest or
effect cannot reuse the ID. Use the E7 proposed 10-second evidence budget
unless that budget is superseded before wire freeze. If a revocation races
after issuance, local application or expiry defeats the proof. A decision
that won the race locally may commit later. This boundary does not require an
atomic AWID and application transaction.

## 4. Public feed

Each dependency version gets an independent cryptographically random handle
when the version is established. Keep it stable across statement renewals.
Allocate a new handle for a successor and keep the mapping in authorised
issuer state. Do not publish names, certificate UUIDs, keys, causes or
predecessor-to-successor links in feed entries or public snapshots. A handle
is recognised only by a consumer that has its matching evidence or mapping.
Raw certificate UUIDs are currently unique per team, and the existing
anonymous status endpoint requires the exact team and ID. Neither is an
appropriate public stream key. See
[AWID private reads and status](../awid-sot.md#signed-team-reads).

Emit a negative handle when a fact stops being current: membership removal
or replacement, team re-key or deletion, subject or ancestor invalidation,
identity-head change, namespace replacement or cut-off, address reassignment,
and routing change where a proof depends on it. Track team incarnations
separately even when a name or key is reused. Track visibility if a proof
depends on it. Same-key custody transfer does not invalidate a fact that
remains true. Preserve the difference between a continuity operation and a
cut-off. Re-admission can issue fresh standing but cannot revive a terminal
grant. Service-owned grant revocations stay out of AWID's feed. Owners enforce
them at their own local gate or distribute their own authenticated
invalidations to separately authorised verifiers.

### Position and barrier

Use an ordered, commit-safe prefix per registry. A cursor identifies the
issuer, stream era and contiguous sequence. The authority change and its
invalidation entries commit together. The initial PostgreSQL implementation
can allocate positions by locking a transactional head row at its final
append, after taking all object locks and before commit. Plain SQL sequences
can reorder visibility or leave aborted gaps. A wall-clock timestamp or a read
of the largest visible sequence does not establish a complete prefix.

A signed barrier names the issuer, era, inclusive last position, prefix
commitment and its observation time. A release must define the hash input
and genesis value in vectors. Use a chained cryptographic hash over each
position and handle so a skipped, replaced or reordered entry cannot extend a
previously verified prefix. The barrier is captured through the same commit
boundary. Publish it only after commit and never extend its age when serving
cached bytes. Operate the signer and distribution with high availability.
Failover must retain the same committed prefix, or advertise an authorised
new era that requires resync. It cannot refresh an older or forked prefix.

### Subscription and on-demand read

A subscription delivers committed ranges and signed barriers. The on-demand
read returns a cacheable contiguous range from the last applied position
towards the latest signed barrier. A request names the stream era and its exclusive starting position. The first
response fixes the target barrier. A continuation binds the same era and
target, advancing only the exclusive start. Responses return range boundaries,
ordered handles and that signed barrier. An expired or foreign-era cursor
indicates resync instead of returning an empty tail.
Stable pages can be retried or shared by caches. The consumer verifies the
complete prefix before advancing the applied point. A duplicate with
identical bytes is harmless. A conflicting position, regressed or invalid
barrier, unexplained gap or unknown era refuses authority until repaired.
A cursor outside retention requires a resync snapshot.

Use one apply implementation for both delivery paths. An on-demand verifier
can use a fresh local prefix that already covers the statement's cut. A
stale or behind verifier signals catch-up through its feed consumer. Coalesce
concurrent requests for the same issuer, and perform the public range read
outside the effect transaction. A request may wait locally for catch-up up
to its budget or return a retryable authority-unavailable result. HTTP
caching, a fresh TCP connection or receipt time grants no freshness by itself.

### Snapshot and retention

A signed public resync snapshot carries one authenticated cut and every deny
handle still able to defeat a valid statement at that cut. It carries no
positive identities or rosters. A private positive projection has its own
authorised provisioning path. Apply the verified snapshot and cursor
atomically, then get a live signed barrier. A restarted verifier cannot become
ready with an empty deny set at the latest position.

Retain an invalidated handle even if the verifier has never seen a statement
that refers to it. For retention, use the first subsequent authenticated
barrier that observed the committed invalidation. Treat its time as an upper
bound on issuance observations that could still have used the old version.
Keep the handle until that time plus 30 minutes and the conservative clock
margin have passed. If the barrier has not arrived, retain the handle. Keep
terminal revocation and current authoritative records at the issuer beyond
that horizon. A restored instance or shorter future lifetime cannot shrink
the window of proofs already issued. If capacity runs out, refuse affected
authority rather than evict a deny that can still match.

## 5. Local decision and E5 binding

Verify signed bindings, holder possession, complete dependencies, the
statement deadline and independent credential deadlines. Use a conservative
bound on current time. Select the exact issuer's authenticated applied
prefix, require its era to match and its cut to cover the proof's cut, and
reject any matching deny handle. A verified new era requires new statements. Require a fresh barrier immediately before a new effect, after any
relevant lock wait. Check authority and linearize admission against the
process's applied view. A failed signature or revoked credential and
unavailable authority are distinct wire outcomes. Preserve the existing
terminal refusal where the route already defines one. Unknown trust or a
stale view never reads as zero revocations.

A barrier's thirty seconds run from its authenticated observation time.
An old barrier received again cannot restart the window. After it expires
there is no authority for new decisions on that issuer until a complete live
point is applied. An already admitted effect can finish. A stream's next
protected emission and a queued operation making a new decision still check
current authority. Scope unavailable authority to the issuer or dependencies
used by the request.

In E5, **run the consumer in each web process** in the existing registry
adapter. Use a live background subscription for the pilot's required
issuers. Each process owns its applied view. Its readiness probe fails
until it has live authenticated authority for its required issuers and fails
again at the 30-second protocol boundary. Requests enforce the
same bound even when a load balancer has not yet acted on readiness.
Unrelated foreign authorities affect only requests depending on them. Keep
process liveness independent so a process can recover. A shared distribution
cache can serve signed ranges to all processes. There is no central Redis
watermark in the pilot's decision gate and no negative or positive AWID
lookup on the request path.

## 6. Federation and cutover

Discover foreign authority outside the request path under the existing
domain and delegation rules. Verify the binding from the authority for that
exact domain to the standing and feed signer before pinning it. Public
distribution does not make an arbitrary issuer trusted. A peer-supplied URL,
unverified key, or evidence from an unrelated fresh issuer cannot substitute.
A split view requires reconciliation. Emergency signer removal uses an
independently authenticated authority path.

The federation destination checks the preserved holder signature and proof
bindings, its local applied issuer views, address continuity and its own
delivery policy. The same ordinary proof can serve source and destination.
Only facts actually used for delivery require evidence. A new send or
effect after proof expiry needs current evidence for that decision. An exact
committed receipt remains an idempotent historical result.

E5 switches once the issuer, feed consumers, clients, applications and
federation peers in its cutover inventory can use the new protocol. After
activation, old requests fail with a discoverable upgrade path. The pilot
does not run the released online verifier alongside this one. A cutover or
rollback has an explicit authority and reconciliation boundary. Preserve the
released behavior at the current service until a separately approved move.
Private reads retain their existing authorization. The pilot verifier no
longer needs the same-operator service token for the per-team revocation list
or per-certificate status read. Other consumers of the token remain governed
by the existing contract.

## 7. Model, conformance and scale

Add the small Design extension beside the atomic trust model. Keep the prior
core and E7 findings. Model untimed predicates for whether a statement creates
authority, is unexpired, depends on an applied invalidation, has a recent
applied feed point, and carries unused exact-request current evidence. Add
allowed and refused neighbours. Prove timing, ordered delivery and effect
races in integration. Then build the executable model and case generator,
including cases an independent verifier can run.

Run the same conformance suite for subscription and on-demand use. It checks:

- Valid proof at two verifiers, wrong issuer/team/credential/purpose, independently
  authenticated foreign chain and team, and fresh evidence for an unrelated
  issuer next to stale evidence required by the request. Reject compact v1
  and existing identity-only requests at statement routes, and exercise
  global-identity mail with the request-bound envelope.
- Committed issuance before and after removal, a proof first presented after
  its deny was applied, credential expiry, stale feed at the cutoff, and
  previously admitted effects that finish. Include stream continuation and
  a write waiting on a lock.
- Exact current evidence, wrong request digest, reuse, unchanged replay receipt,
  and the absence of effects on issuer refusal or stale destination evidence.
- Aborted and reordered transactions, missing or changed entries, duplicate
  entries, stale and replayed barriers, snapshot resync and era change. A
  bootstrap snapshot includes still-live denies for versions it never saw
  as positive evidence. Stop the signer and distribution separately. Both
  transports recover only with a complete live point.
- Distinct teams with the same certificate UUID or key, recreation, ancestor
  invalidation and retained terminal grants. Unrelated facts remain eligible.
  Inspect public responses and snapshots for raw identifiers or joinable
  successor mappings.
- Fresh local reuse and coalesced on-demand catch-up; no request-time fallback
  to AWID, even on a cache miss or error.

The scale gate seeds one team with one million active synthetic members and
ten million historical revocations, plus a foreign registry and a private
team. Compare one hundred times less history at equal current change rate.
Measure issuance, signer queues, commit lock waits, feed bytes, subscriber
lag, denied-handle memory, catch-up and resync cost, request throughput and
clock error. The steady-state work must be independent of history outside
the deny horizon. Count and reject every inline registry/DNS authority read
at the request boundary. Keep initial snapshot work and authority-change cost
visible separately.

At 30 minutes, one proof per active binding costs about 556 signatures/s for
one million bindings and 5,556/s for ten million before early renewal and
retries. At an 80% refresh interval, about 694/s and 6,944/s respectively.
Two independent proofs per binding double those numbers. Extra verifiers for
the same binding add no issuance. Benchmark the deployed signer, indexed
registry reads and both feed transports rather than extrapolating from raw
signature operations.

| Implementation boundary | Acceptance |
|---|---|
| AWID issuance and signer | Consistent committed read, scoped ordinary and exact-request proofs, protected signer, issuance refusals and byte vectors. |
| AWID feed and public snapshot | Complete mutation inventory, atomic append, signed barriers, both feed reads, retention and scope-preserving resync. |
| Verifier SDK | Local validation and shared apply logic; published conformance for both transports. |
| aweb runtime and grants | Complete request inventory, local gates and typed refusal, owner-held grant/application facts, effect and stream tests. |
| Federation | Two-registry interoperability, exact trust bootstrap and recovery, no request-time authority fetch. |
| Pilot/clients | Per-process E5 consumer, readiness, clients and operator documentation, one-cut rehearsal. |
| Scale and integration gate | Reproducible history, traffic, change, partition and recovery fixtures with stated hardware and measured limits. |
