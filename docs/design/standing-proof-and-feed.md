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

Statement, feed-barrier, snapshot and era-transition signatures have
distinct versioned purpose labels. The proposed byte encoding is Ed25519 over the ASCII purpose
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

### Holder request and replay

The holder signs the purpose `aweb.standing-request/1` followed by a newline
and the canonical request payload. This label is distinct from compact v1,
request-bound v2, identity-only, mail content and the current-evidence issuance
request in §3. Verifiers select the request type by the route and reject an
envelope of any other type on statement routes. E5 migrates global-identity
mail from today's identity-only envelope to this request-bound envelope,
still signed by the identity key. DID and address routing still work without
an invented team selection.

The canonical payload covers the version, canonical service audience, HTTP
method, raw path including query, operation, exact actor scope, SHA-256 of the
body bytes, SHA-256 of the canonical ordered array of attached evidence
envelopes, and a UTC timestamp. Include the operation ID or nonce when the
route requires one. A configured or authenticated service identifier determines
the audience. The request's Host and forwarding headers do not. Compare
the method and raw target with the effective externally signed request at the
trusted serving boundary. The request timestamp may be at most 60 seconds
old and at most 2 seconds ahead of the verifier, with the conservative clock
bound in §5. Verify the holder signature separately from the issuer statement.
The timestamp limits replay exposure. The route class determines whether a
replay can take another effect.

| Route class | Replay rule within the signed window |
|---|---|
| Pure reads and read-only stream admission | An identical request can be checked again against current local authority. Signing a read does not acknowledge, mutate or permit later emissions. |
| Durably idempotent or conflict-safe data writes, including mail/chat delivery with an immutable message ID | Accept the same exact operation and actor with the original canonical inputs at most once. Record its receipt with the effect and outbox. A repeat can read the same receipt if still entitled, while the same ID with changed inputs refuses. |
| Authority creation and every remaining effectful route | Consume a one-use ID with the effect. Authority creation uses the ID in its exact-request evidence. Other routes in this class use a holder-signed random nonce scoped to the actor, operation and service. A repeat gives only an entitled receipt or a replay refusal. Keep consumed IDs through the full accepted replay window, including clock uncertainty. |

Classify every enabled route, including app mutations and stream
acknowledgements, in the cutover inventory. A route with no class is disabled.

Keep private positive issuance at the existing authorised boundary. One issuer
must not grant read access on another issuer's behalf. A grant worker needs
scoped authorisation to obtain its resident's evidence without getting the
resident's signing key. The grant journey must prove that an expired or revoked
grant cannot use a still-valid resident statement and that evidence issuance
confers no access to the private roster.

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

Any effect that creates or widens authority which outlives the request needs
current evidence for that exact act. For member-derived acts, the holder
obtains it from the registry. A controller act at AWID itself or an act wholly
owned by the service applies the same current decision and one-use rule inside
its own authority transaction.

Classify grant mint, connect, app install and app-request approval. Also
inventory API key issuance, temporary access, hosted-connector tokens, invites,
hook and webhook bindings, member-key enrolment, and contact or reachability
changes that grant access. A request for approval that grants no authority
can stay ordinary. A route requiring current evidence stays disabled until
the issuer, exact inputs, owner and lifetime have been identified.

The holder signs the separate issuance purpose
`awid.current-standing-request/1`. The canonical intent binds the registry
as issuance audience and specifies the destination service, operation,
method, raw path and query, actor scope and body digest. The intent excludes
the returned evidence and its destination request signature. The registry
checks the request and relevant standing at its current committed cut and
signs the intent, dependencies, exclusive expiry and one-use ID. The
destination compares its signed request to the attested intent. An ordinary
statement cannot satisfy this proof type. Stage an app manifest before
requesting current evidence for its exact digest and scopes.

At the destination, check the bindings, expiry and applied prefix after the
last relevant wait. Consume the ID with the effect in one transaction. A
retry of the same request may read its recorded receipt. A different digest or
effect cannot reuse the ID. Use the E7 proposed 10-second evidence budget
unless that budget is superseded before wire freeze. If a revocation races
after issuance, local application or expiry defeats the proof. A decision
that won the race locally may commit later. This boundary does not require an
atomic AWID and application transaction.

The owner records the actor and authority provenance with every created
authority. For a personal delegation such as a session grant, current
evidence also identifies the issuer-scoped handles for the minter's
continuing authority lineage. The owner records and checks these on grant
use. A terminal change to that authority denies its lineage handles. If
admission wins the race and the deny applies before its write commits, the
resulting row cannot authorise a use. Check this in the owner transaction
or at use against the same authority fence. Persist terminal ends. A later
re-admission receives different lineage handles and cannot revive the
delegation. When the governing rule has continuity across credential
renewal, the assertion-version handle can change without denying the
continuing authority lineage.

The owner must preserve terminal ends beyond the feed's proof-retention
window. After a missed interval outside retention, it must re-establish
the original live authority lineage through an authorised recovery path
before serving dependent delegations. Fresh standing for a newly admitted
subject proves only its new authority. A record whose grantor is the
organisation, such as an installation backed by an authorised organisation
decision, can outlive the presenting member. Its route must name that
authority explicitly and define the owning administrator or service
revocation path. Member-derived authority is the default when a route
supplies no independent organisation authority.

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
of the largest visible sequence does not establish a complete prefix. The
scale gate's initial acceptance target is **p99 head-lock wait at most 5 ms**
at **1,000 authority-changing transactions/s** on the stated registry
hardware. Record the sustained commit rate and barrier age during that run.
A missed target calls for changing the implementation within the same
committed-prefix contract.

A signed barrier names the issuer, era, inclusive last position, prefix
commitment and its observation time. A release must define the hash input
and genesis value in vectors. Use a chained cryptographic hash over each
position and handle so a skipped, replaced or reordered entry cannot extend a
previously verified prefix. The barrier is captured through the same commit
boundary. Publish it only after commit and never extend its age when serving
cached bytes. During idle periods sign a new barrier at least every 5 seconds,
even when the position and commitment are unchanged. Use a dedicated
barrier-signing key and isolate barrier signing and distribution from
routine issuance in capacity, processes and operational failure domains.
Distribution serves signed bytes and holds no signing key. Barrier and
statement signers share only the underlying authority data they need. An issuance-only outage denies current-evidence acquisition
and refresh, while already issued ordinary proofs can continue until their
own deadlines, up to 30 minutes, if barriers remain live.

Authenticated admission depends on the availability of the barrier signer
and distribution. The residual recovery budget is only the unused portion
of the 30 seconds from the last applied point. The E5 target is 99.99% of a
rolling 30-day window with a live applied point from each required issuer
at representative healthy verifier locations, and p99 applied age at most
10 seconds at the scale gate. Measure the signer path, distribution and
verifier apply lag separately.

An ordinary failover continues the same committed prefix. An era transition
must be signed by the scoped authority, bind the prior published prefix and
the successor genesis, and require resync. Before starting a new era, prove
the authoritative data includes the prefix of the last published barrier
and settle all later committed outcomes. If that floor cannot be proved,
require an operator-authorised incident recovery. Fence issuance and
admission until the authoritative records have been reconciled or the
affected credentials have been explicitly invalidated through their proper
authority. A new era alone cannot clear revocation or refresh a forked
prefix.

### Subscription and on-demand read

A subscription delivers committed ranges and signed barriers. The on-demand
read returns a cacheable contiguous range from the last applied position
towards the latest signed barrier. A request names the stream era and its
exclusive starting position. The first response fixes the target barrier. A continuation binds the same era and
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

A signed public resync snapshot carries one authenticated cut, the chain
commitment at that cut and every deny handle still able to defeat a valid
statement there. Following ranges must extend that commitment. It carries
no positive identities or rosters. A private positive projection has its
own authorised provisioning path. Apply the verified snapshot and cursor
atomically, then get a live signed barrier. A restarted verifier cannot become
ready with an empty deny set at the latest position.

Keep each issuer's authenticated old-era denies across resync for their
remaining 30-minute horizon plus clock margin. Compare handles by issuer
and handle even across eras. The replacement snapshot includes still-live
denies from previous eras. Its application merges those with local
authenticated denies. A store restart cannot discard the local deny state
and declare a recovered era ready from an unproven snapshot. Reusing a
dependency version keeps its exact handle across eras. A deny remains
effective even if an incorrect restored issuer reattests that version.

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
statement deadline and independent credential deadlines. The maximum
issuer-to-verifier clock error is **2 seconds**, including measurement
uncertainty. Use verifier UTC plus that bound for issuer-time expiry and
barrier age. Refuse to establish verifier readiness while this bound is
unknown or exceeded. After bootstrap, refuse affected authorization requests
when time is unsafe. Never extend the window to tolerate clock loss.

For each presented proof independently, select its exact issuer's applied
prefix. Require its era to match and its cut to cover that proof's cut.
Reject any matching deny handle. A request relying on two issuers needs
both views. A verified new era requires new statements. Require a fresh
barrier immediately before a new effect, after relevant lock waits.
Check authority and linearize admission against the process's applied view. A failed signature or revoked credential and
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
adapter. Use a background subscription for the pilot's required issuers.
Each process owns its applied view. Its readiness probe gates bootstrap on
a live authenticated prefix and healthy bounded clock. Once bootstrapped,
loss of an issuer refuses requests that require that issuer at the effect
gate. Keep the process in the load balancer so public routes and other
issuers' routes can serve. Keep liveness independent. A shared distribution
cache can serve signed ranges to all processes. There is no central Redis
watermark or AWID lookup in the pilot's decision gate.

On stream authority loss, end the affected stream with a retryable
authority-unavailable reason before another protected emission. The client
keeps its last accepted cursor and reconnects with a newly timestamped
request. Use exponential backoff starting at one second, capped at 30
seconds, with independent jitter across clients. Honour a longer
Retry-After and add jitter to it. Reset after a healthy admission. This
spreads reconnects and preserves replay handling after a fleet-wide loss.

## 6. Federation and issuer discovery

Discover foreign authority outside the request path under the existing
domain and delegation rules. Verify the exact domain's issuer association
and the registry authority's current standing key set before pinning a
signer. The [organisation records and issuer trust design](standing-organisation-records.md)
specifies those two checks and the withdrawal bound. Public
distribution does not make an arbitrary issuer trusted. A peer-supplied URL,
unverified key, or evidence from an unrelated fresh issuer cannot substitute.
A split view requires reconciliation. Emergency signer removal uses an
independently authenticated authority path.

Resolve the issuer per exact domain, using its authenticated `_awid`
discovery and any required delegation evidence. A configured client
default cannot override a domain's authenticated `registry=` binding.
An explicit trusted pin can establish an issuer without performing discovery.
Cached discovery can supply a still-valid scoped pin through its established
lifetime. When a discovery read is required, missing, malformed, ambiguous
or unavailable discovery leaves authority unavailable. A conflicting
authenticated result requires reconciliation.
Never try a different registry or protocol after a failed lookup or proof.
Apply these rules to clients, discovery workers and pilot control-plane
writes as well as federation. The released general-purpose AWID SDK shortcut
that bypasses discovery for a non-default registry is unsuitable here.

For a relayed send, the holder signs a submission envelope for the source
service and a distinct delivery envelope for the destination service. The
source verifies its own audience and the holder's destination signature,
and checks that the delivery binds the exact resolved destination, sender,
recipient, immutable message ID and body it is relaying. The relay carries
the holder's destination-bound bytes and supplies any separately required
relay authentication. The destination verifies its own audience, never the
source's. It checks proof bindings, its own applied issuer views, address
continuity and delivery policy. The same portable standing can accompany
both requests. A delayed new delivery whose signed window or proof has
expired requires new holder-signed evidence for that delivery. An exact
committed receipt remains an idempotent historical result under its existing
access rule.

Mail delivered before cutover retains its receipt and verification treatment.
The recipient verifies the original stored signed artifact under its original
message contract. Reading it does not require a new holder envelope or a
standing statement. The cutover alone changes neither the historical receipt
nor whether a previously verified message displays as verified. A new reply
uses the new request envelope while preserving the existing source-message
and recipient-binding checks.

### Frozen and standing-protocol peers

Select the client from trusted domain and service configuration before
signing. The released `aw` speaks the released contract for the frozen
service. The new `aweb` speaks only the standing contract for E5. E5's
serving routes accept only the request-bound protocol in §2.

**E5 launch scope.** On 2026-11-28 Juan decided that E5 serves
`awebai.org` with standing and refuses cross-federation with frozen
`aweb.ai` in both directions. The launch has no mail bridge or online
ingress adapter. E5 onboards the agents on `juan.aweb.ai` and the OATS
team with fresh `awebai.org` identities (§7). The frozen service and
`api.awid.ai` keep serving their existing identities and customers.

Give the initiating client a typed unsupported-peer refusal when trusted
discovery identifies a released-only peer. An unknown or unreachable
authority retains the authority-unavailable refusal. Apply the same
no-effect rule at ingress. E5 fails closed with zero request-time
authority lookups. Native federation between admitted
standing issuers remains part of OSS conformance.

## 7. First deployment and future customer migration

On 2026-11-28 Juan authorised a second AWID registry for E5 on
`awdid.org`. This design uses `https://api.awdid.org` as its production
origin. The `_awid.awebai.org` record binds the namespace controller and
`registry=https://api.awdid.org`. The frozen `aweb.ai` service keeps
`https://api.awid.ai`. Use the normal landing and deploy gates. The
operator records the change window before deployment and DNS changes.

### Registry operation and bootstrap

The `servers` repository owns the deployment definition. The hosted
operations seat runs the registry, including on-call, signer and feed
monitoring, backup and recovery. E5 owns the pilot adapter and onboarding
journey. Give the registry its own origin, deploy unit, database, state and
credentials. Build once, qualify the image digest and deploy that digest
with a migration report before traffic. Keep the statement signer and
the barrier signer separately protected and highly available. Replicate
public feed distribution and serve signed ranges through cacheable reads.
Only a verified applied point establishes freshness. Alert on signer
queues, barrier age, applied lag and loss of the measured clock bound.

The registry's operational proof, barrier and recovery keys have separate
custody and access policy. The domain controller selects the issuer.
The registry authority publishes and rotates its purpose keys.
They confer no controller or membership
authority. Under Juan's 2026-11-28 decision, the background worker alone
holds the `awebai.org` namespace controller key in its worker-only secret
mount under the Render file checks described below. The coordinator's pilot
plan puts the admin and open team keys in the same mount, pending Juan's
review. Bootstrap the first chain at the new registry with those
authorities, using the exact staged admin identity and team binding.
Before signing, the worker independently
establishes the authority for the requested operation. The external watcher
checks the namespace controller and both team keys against the operator's
out-of-band approved-change record. The operator retains DNS recovery
authority as described in
[the issuer custody design](hardware-backed-personhood.md#81-settled).
Private reads retain their existing authorization.
The native pilot verifier needs no same-operator token for revocation or
certificate status. Any other permitted use keeps its exact-origin scope.

Back up the database and feed state with encrypted point-in-time recovery.
Protect signer recovery material separately. Retain authenticated published
barriers independently of the database being restored. Rehearse failover
and restore against the latest published prefix, including issuance, deny
retention and snapshot/tail verification. Fence issuance and publication
if continuity with that prefix cannot be proved. Recovery uses the
authenticated incident procedure in §4.

The pilot's inventory found no existing `awebai.org` registration. Recheck
the domain's DNS and authoritative namespace before provisioning. If the
inventory holds, E5 is a first deployment. Qualify the new registry and
its trust binding, then publish the exact `_awid.awebai.org` record and
bootstrap the namespace and first chain. Bring up each pilot consumer
through its readiness gate, then enable E5 clients and routes. Rehearse
that order with the pinned old and new registries. If existing state is
found, stop and reconcile its authority and history before bootstrap.
Rollback stops new E5 effects while preserving committed state for
reconciliation. Once the new registry has accepted writes, pointing DNS
elsewhere cannot serve as rollback.

### First-deployment onboarding

Onboard the `juan.aweb.ai` agents and the OATS team as new holders under
`awebai.org`, using the new registry's ordinary first-deployment admission
paths. Issue fresh identities, addresses and team certificates under the
destination authorities. Establish new contacts for the cohort. Its existing
DIDs, credentials, addresses, contacts and verified mail stay usable in
their frozen homes under the existing controller. The frozen `aweb.ai`
service and `api.awid.ai` keep their released contract.

Install the standing client alongside the released `aw`. Its provisional
binary name is `aweb`. Each client has its own config and identity homes.
Select the binary, home and issuer explicitly. A client refuses the other
client's home, including when it is supplied by a flag or environment
variable. A lookup, proof or request failure cannot switch binary, home or
issuer. Qualify the paths each seat uses, including hosted MCP,
self-custodial homes, OATS bindings and installed apps. The OATS provider
selects the client and home per seat through its integration contract.

To use frozen service during an outage, the operator explicitly selects
`aw` and the agent's existing frozen identity. It has its own DID, key,
address and team certificate. Only its frozen controller grants or revokes
its membership. The new service's authority applies to its own identities.
Old conversations and verified mail stay in the old home. New identities
start new conversations. New mail uses the new addresses and contacts.

### Future customer migration

Moving an application's delivery origin and transferring a namespace's
registry authority are different operations. A delivery move can retain
its registry if that issuer supports the target protocol. Transferring a
namespace while keeping its identities requires a separately approved
transfer protocol. A DNS change publishes the selected authority. The
transfer must prove continuity of that authority and its facts.

The transfer must fence source writes and issuance, verify a final source
cut, and verify the destination before switching DNS and verifier pins.
Preserve stable DIDs, signed chain and key history, controller history,
ancestor cutoffs and terminal revocations. Carry surviving denies and retire
old authority at the source. When moving a team's service authority, the
moved team starts with a fresh signing key and new certificates for an
explicitly authorised current roster. Keep old team keys, certificates and
revocations as historical records only. Exclude
stale writers and issuers throughout the transition. The grant owner must
account for its own delegation state or require new grants.

The first deployment follows the onboarding path above. The approved
registry transfer of the `aweb.ai` hosting tree follows the
[single-window procedure below](#transfer-the-hosting-tree-in-one-window).
A customer move that changes service authority requires its own product
decision. For such a move, collect
holder migration statements and controller-signed rosters before the
source fence. Verify the prepared source heads, roster and key versions
against the fenced cut. Exclude unresolved bindings, fence those source
bindings and keep their destination admission closed. Move them later
through authorised recovery or admission. Activate the ready subset only
after independently verified source retirement.

Set the reversible fence budget and reserve enough time for the measured
retirement and activation steps. Rehearse a 30-minute cap as the starting
budget for planning a future move. Before the first irreversible
retirement, abort if the ready subset cannot finish within the approved
budget. Reconcile paused effects before resuming eligible source writes.
After retirement starts, keep affected writes fenced for reconciliation.

#### Refusals for a later customer move

These two refusal contracts apply to a separately approved customer
move. For a known moved binding, an old request receives a typed
`standing_upgrade_required` refusal with the new issuer and the standing
request contract. Check the refusal
on the stale client entry point as well as at the destination. Any
source-side response is scoped to exact moved bindings and grants no
delivery or authority. The released client must display a usable upgrade
message. Trusted issuer discovery still governs the next request.

An otherwise authorised send to a known retired address receives a typed
`address_retired` refusal. An unknown address retains the existing
unknown-recipient response. Include a replacement address only when the
recipient expressly opted in and the replacement binding is current and
verified. The refusal itself never forwards or delivers.

#### Customer migration gates

These gates cover a move of customer service authority. The registry-only
hosting-tree procedure below uses the same verified-cut, exclusion of
concurrent writers and reconciliation rules at its registry boundary.

1. **Fence and authenticate the source cut.** Stop ordinary authority
   writes, admissions and sends for the moving scope at the source.
   Reconcile accepted deliveries and outbox jobs. Export the scope in a
   consistent source database read while fenced. The released registry
   supplies no standing statements or signed feed for this cut. Verify
   each identity log and available signed namespace, delegation, address
   and controller artifacts under the released contract. Where a
   released write left only a database projection, verify it against
   the fenced read and obtain an explicit scope-bound confirmation from
   the recorded controller. Require original signed evidence wherever
   the contract requires it. Do not silently replace missing evidence.
   A dedicated operator migration key signs a canonical manifest binding
   the source, destination, scope, fenced heads, inventory and its digest.
   Record that digest out of band. An independent verifier with access to
   the fenced source recomputes the inventory, heads and hash and verifies
   the signed evidence. A manifest signature alone establishes neither
   completeness nor the validity of a row.
2. **Prove live identity continuity.** Each moving global identity signs
   a purpose-versioned migration statement with its current key,
   binding the prepared migration instruction, registries, stable DID,
   source log head and exact destination address and route, or its
   explicit unaddressed status. Bind the accepted instruction and
   statement to the final manifest. Require the signed head and imported
   head to equal the independently read fenced source head, verify the
   log and chain through that head, and verify the holder signature with
   the key at that head. Require the applicable namespace and routing
   authorities to sign the destination binding. A holder missing its current key
   takes the recovery path before it can move. A team-local identity
   has no portable global DID or address. Preserve its holder binding
   only with verified continuity of the team and key, and record any
   fresh local enrolment explicitly.
3. **Re-issue team authority.** Every moved team uses a fresh team
   key version or a new incarnation with a fresh key. The controller
   signs the explicit roster in advance, including exact holder, alias
   and authorised role for each member and the exact source team basis.
   Compare it to the fenced source. The controller signs fresh
   certificates only for the approved ready set. Old certificates,
   public verification keys and their revocation history serve audit only.
   The destination verifier can admit only the new team binding and
   key. Import terminal identity revocations and relevant cutoff state
   before issuance. Rebind agent homes and workspaces, and reissue or
   reconcile grants under their owning service.
4. **Retire the old authority before activation.** Under the migration
   fence, the source team controller revokes or retires as moved every
   old certificate of the moving holders at `api.awid.ai`. Record
   those acts and independently confirm that the frozen service refuses
   the old credentials, including after a warmed cache. Retire applicable
   existing grants and other retained source credentials with their owners.
   Keep the fence until the source effect gate observes retirement.
   Namespace and identity transfer must also retire active old authority
   for the moved scope. Historical reads can remain available.
5. **Preserve mail and switch.** Import or expose authenticated
   read-only history under the same recipient entitlement. Preserve
   original signed artifacts, conversation IDs, receipt and verification
   state, and ciphertext and key references. Keep decryption custody with
   its holder. Reconcile all accepted message IDs before opening the
   new inbox. Settle an accepted old send against its original receipt.
   An unsent delivery needs a new destination-bound request when its
   route changes. A reply to a migrated participant keeps its conversation
   and uses the current verified route. A reply across the frozen boundary
   reports the unavailable route. Keep old writes fenced after activation.

Run the rehearsal against a real source and destination. An independent
verifier enumerates **every** historically revoked certificate in each
moved team and **every** rotated-away identity key for the moving
identities from the fenced source inventory. Check that the destination's
authority checks refuse each for its exact old credential binding, using
the preserved artifacts and known keys. A missing possession proof or
unavailable service is insufficient evidence of refusal. Check the
source refuses each moved holder's old certificate before opening the
destination. Require positive controls for current reissued members and
matching identity, address, team and mail inventories. Verify that one
activation opens the ready cohort and that excluded bindings remain fenced.
Rehearse a source-head change, an unresolved holder and a pre-retirement
abort within the time budget. Check that historical mail remains readable
with its original verification and an exact retry yields one receipt and effect.

### Hosted child registration and registry transfer

The hosting-tree registry move is separate from E5. Moving the hosting
parent's controller out of the service requires operator approval. The
frozen service uses that controller to create customer namespaces. Its
registry has no registration-only key. As soon as the controller leaves the service,
automated sign-ups that need a new child pause. They can continue only with
an outside controller signature for each new child or after moving sign-up
traffic to a live provisioner lane. Time the key removal with that lane and
traffic switch unless the operator approves the pause or outside signing
for the gap. Complete step 0 below before removing the key or transferring
the parent. Keep the controller key outside the service after removal.

Control of DNS lets the operator recover the parent with a new controller
key. Recovery restores control of the parent. Repair of earlier effects is
separate. The full parent controller can use the parent-authorised
recovery PUT to replace a child's controller, even when the child has its
own key. That opens a `replaced` epoch and cuts off the child's earlier
tree. Recovering the parent leaves those cutoffs in place. Restore the
child's authority and explicitly re-admit the affected bindings.

Parent key-loss recovery itself withdraws the old outgoing delegation
witnesses. An unchanged child that relies on inheritance needs a new
registration signed by the child and the new parent. A child with valid
exact authority can still verify independently. A shared-key child also
used the compromised key as its own controller. Changing the parent's
DNS leaves the child's stored key and epoch as they were. Step 0 gives
children independent keys and recovery paths, while parent recovery can
still require work across the inherited inventory. See
[namespace continuity and replacement](../id-certificates.md#namespace-continuity-and-replacement).
The provisioner key limits exposure to claims on unused allowed names
until its grant ends.

#### Registration-only key

The parent controller authorises a dedicated provisioner key with a
registry-bound, controller-signed record for the exact parent and its open
epoch. The record names the key, its expiry and the registration-only
purpose. The controller alone can replace or withdraw it. Use the
[namespace-controller record pattern](standing-organisation-records.md#1-encoding-and-authority)
for the record and its revision, without making the grant a discovery key.
The provisioner key is separate from the parent's controller and from every
child controller. It carries no DNS update authority.

The registry accepts the provisioner's parent proof only on first
registration of a direct child. A purpose-separated proof binds the grant
revision, registry, exact parent, canonical child and proposed child
controller to the registration request. The child controller proves
possession through its own covering signature. The registry checks that
inherited discovery names this parent and registry, and refuses an exact
child record for the provisioner lane. Under the parent authority and child
name locks, it rechecks discovery freshness, the grant, parent epoch,
expiry, label policy and absence of any prior or reserved child. A deleted, migrated, or reserved
child is unavailable to this lane even if there is no live row. Seed those
reservations from the reviewed inventory before opening the lane. A
byte-identical retry may retrieve the original receipt without changing
state. Conflicting claims refuse. The released controller-signed path keeps
its own authority rules.

The provisioner cannot reaffirm, transfer, replace, recover, delete or
withdraw an existing child, or publish records for the parent or child. An
operation that already needs the child or full parent controller still needs
it. The delegation witness records the **parent controller** and the child's
registered key as before. Keep the provisioner key, grant revision and
request digest as private registration provenance. They are useful to
investigate unwanted new names and confer no continuing authority. The
child controller signs its own D2 issuer association and any organisation
records under its own epoch. A child key in hosted custody still has the
ordinary powers of that child controller. The protection here requires
keeping the parent controller and DNS change authority outside the
provisioner.

Replacing, expiring or withdrawing the grant closes future provisioning,
including a queued request that has yet to pass the locked check. A parent
epoch change ends the grant and requires a new authorisation. These changes
leave committed child facts intact and emit no standing deny. If the
controller subsequently withdraws a delegation or retires a child, the feed
emits the handles for facts actually ended under §4. A provisioner leak can
claim still-unused, allowed names until the grant ends. Reconcile those
registrations under the controller path.

A hosting parent may reserve a closed set of canonical direct-child labels.
The operator owns the policy and the selected registry's published set for
the exact parent is authoritative. AWID applies it to fresh registration
regardless of the registration proof, with a typed refusal for a reserved
label. Existing registrations stay intact. The hosted sign-up service's
copy is only a pre-check for local refusal and messages. Its acceptance
gate refuses a release if the canonical sets differ. On a reservation
change, a mismatch disables the service's pre-check and is reported.
AWID still decides, and the service maps its typed refusal.
Hosting-zone policy prohibits child NS delegation and wildcard AWID TXT
records. Apply it in the zone configuration and validate the published
zone before transfer. The single-window procedure relies on every live
child inheriting the same parent record.

#### Transfer the hosting tree in one window

On 2026-11-28 Juan approved moving the parent and all 449 live `aweb.ai`
child namespaces together from `https://api.awid.ai` to
`https://api.awdid.org`. For the registry transfer, every
namespace keeps its name, addresses and keys from the verified post-step-0
source cut. Include all live children regardless of activity. Any decision
about retiring dormant namespaces belongs to a separate operation.

**Open decision for Juan — customer service and client at the switch.**
Approval of the registry transfer leaves two ways to serve the customers.
Set the service contract before rehearsing the live cut.

1. **Move service authority at frozen-app sunset.** Time the registry
   transfer to the move to the new hosted service at `dashboard.aweb.ai`.
   Customers then use the standing contract and their agents need the
   standing-only `aweb` client. Apply the service-authority migration gates
   above in addition to the registry transfer. The namespace controller
   and identity keys carry over. Every team gets a fresh signing key and
   reissued certificates for its approved roster. Rehearse the re-key and the
   client and service change, including the typed upgrade refusal from the
   released client and a working journey with the standing client.
2. **Keep the frozen service through sunset.** Move registry authority
   first. Through the inherited `_awid.aweb.ai` record, frozen Cloud and
   released `aw` would discover `api.awdid.org`. That registry would serve
   the exact released read and write contract these clients use until
   sunset. Inventory the routes and match their auth, request and response
   behavior against the pinned frozen Cloud build and released `aw`.
   Include namespace and delegation, address, identity-log, team and team
   certificate, certificate status and revocation, and member-lookup
   operations. Rehearse frozen Cloud and released `aw` against the
   destination through inherited discovery. Exercise sign-up, mail,
   team join and leave, and certificate status.

The coordinator recommends the sunset move so the destination can use the
standing contract without a temporary released-contract bridge. That option
changes every customer's client and re-keys every team. Juan's decision and
the corresponding end-to-end rehearsal are required before the live switch.

0. **Separate shared controllers (`aweb-adyx.14`).** Before either
   parent-controller key removal or the parent transfer, build the live child
   inventory from source AWID rows. Join it to the service's custody data.
   Reconcile registry-only names and stale service status before acting.
   Give each child whose controller equals the parent's a fresh
   per-child controller key in frozen custody, using the existing two-key
   `POST /v1/namespaces/{domain}/rotate` under its old and new child keys.
   Use the valid inherited witness while it still agrees with the old
   child key. Where a child already uses exact DNS, coordinate the exact
   record for the successor key on the source registry. Both paths open a
   `rotated` epoch and preserve registered identity history. The recovery
   PUT opens a `replaced` epoch and cannot serve as a continuity fallback.
   If an old registration lacks an open epoch, establish it first through
   the existing reaffirmation path.

   Operations owns and rehearses the custody tool with a designated canary.
   Stage the key in frozen custody and fence affected namespace writes until
   the registry and service agree on the new controller. Confirm the rotated
   epoch, existing registered chains and namespace-key operations including
   ID issuance, team operations and address publication. Check any carried
   root-signed evidence under the successor and arrange replacement where
   required. Reconcile an interrupted rotation against the actual source
   head before resuming writes. Fence provisioning that could add a
   shared-controller child before the final inventory check. Both key
   removal and parent transfer wait for that check to show no remaining
   shared controllers. Step 1 preserves the resulting per-child controllers.

   The source inventory for this move identifies every live child
   controller as hosted. Signing readiness requires proof of the shared
   old controller key. Rehearse a challenge signature through the custody
   tool against a representative store, then verify a fresh signature from
   approved source custody against the shared public key in AWID. Keep
   private material within custody. If a custody row cannot supply the
   shared key, obtain the old-key proof from the original parent key in
   its existing custody. Without that proof, step 0 stays incomplete and
   neither key removal nor transfer proceeds. Operations supplies the
   namespace-controller signatures once custody is confirmed.

1. **Prepare and verify the whole tree.** Before the window, finish step 0
   and rehearse the entire sequence on a representative copy of both
   registries. For the live cut, fence source provisioning, authority writes
   and issuance for the parent and its children. Use the verified source cut
   and manifest rules above for the entire scope. Enumerate all 449 children
   from source AWID and reconcile every entry before moving the parent.
   Confirm through DNS that every child resolves through the parent record.
   Any overriding exact child record or unresolved authority holds the move.
   The switch uses the existing parent TXT record, with every child resolving
   by inheritance throughout.

   Stage the parent and all children at the destination with the same names,
   stable DIDs, addresses, controller and other current keys, delegation
   witnesses, epochs, history and cutoffs. Verify revocations, inherited
   authority and current records independently against the fenced source.
   Obtain parent and child controller authorisations for the exact cut and
   destination. Operations signs within each existing custody boundary. Bind
   registry-scoped records to the destination where the record format
   requires it, and retain the original source evidence for verification.
   The signed transfer evidence allows §6 verifiers to reconcile the new
   registry and issuer to the exact preserved facts. Keep destination
   writes and issuance fenced pending activation.

   **Full negative inventory.** The independent verifier enumerates from
   the fenced source every historically revoked certificate in every moved
   team, every rotated-away identity key, and every cut-off epoch or
   withdrawn delegation. Reconcile the exact entries at the destination
   with the source, including equal per-team counts and counts for
   namespace-scoped entries. Prove that the destination's authority checks
   refuse each exact old binding for the applicable reason. Use preserved
   signed artifacts and test a current binding alongside the refusals.
   A migration fence, missing possession proof or unavailable service
   cannot substitute for a refusal by the destination authority check.
   The verifier records each result against the fenced cut and the exact
   destination build and inventory used for activation.

2. **Flip the parent and verify.** Change only the registry endpoint in
   `_awid.aweb.ai`, keeping the parent controller in that record. Check the
   operator-designated customer namespace first, then verify the parent and
   all 449 children at the destination. Check cold and warm discovery and
   verifier pins, the inherited parent witness, the current authority at
   each exact child, and continuity of the admitted keys, addresses and
   deny inventory. A prior source pin needs the authenticated transfer
   evidence before it can select the destination. An unresolved pin or
   inconsistent read refuses under §6. Keep effects fenced at both registries
   while checking the switch.

3. **Abort or retire source authority.** Reserve time for verified retirement
   and destination activation within the rehearsed window. Abort before the
   first irreversible source retirement if a check fails or the full cut
   cannot finish in the remaining budget. Restore the parent DNS record to
   the source, reconcile pins and paused effects, and verify source
   authority before resuming source writes. Keep the destination fenced.
   Proceed only when the independent full negative inventory has passed
   for every entry with matching per-team counts, the selected service
   contract has qualified, and the whole cut and remaining budget verify.
   Retire the source's serving authority for the entire tree and verify that old
   authority is refused, including with warmed caches. Preserve historical
   source evidence. Only then enable destination writes and issuance for
   the whole tree. If retirement has begun and cannot finish, keep effects
   fenced for reconciliation.

Rehearse the full-size inventory and the single DNS flip before the live
window. Exercise a stale parent answer on a warm verifier, a child with
unresolved source evidence, the first customer check failing, and the
pre-retirement abort back to verified source. On a successful run, verify
all original addresses, current keys and delegation witnesses at the
destination and refusal of retired source authority. Run the independent
negative inventory against the full rehearsal cut and compare per-team
counts and exact refusal outcomes. Exercise a missing deny entry and show
that activation is held. Use released clients for the source checks and
qualify the selected service contract and each of its clients at the
destination.

Separately qualify the registration-only lane with a fresh child and
refusals for existing, deleted, migrated and reserved names. Race grant
withdrawal and parent rotation against registration. Verify that withdrawal
stops new creation while a committed child still verifies. Verify that
parent key-loss recovery leaves any already committed child `replaced` epoch
in place and that a delegated reaffirmation restores an otherwise
unchanged child's inherited proof.

## 8. Model, conformance and scale

Add the small Design extension beside the atomic trust model. Keep the prior
core and E7 findings. Model untimed predicates for whether a statement creates
authority, is unexpired, depends on an applied invalidation, has a recent
applied feed point, and carries unused exact-request current evidence. Add
allowed and refused neighbours. Prove timing, ordered delivery and effect
races in integration. Then build the executable model and case generator,
including cases an independent verifier can run.

Run the same conformance suite for subscription and on-demand use. It checks:

- Valid proof at two verifiers, wrong issuer/team/credential/purpose, two
  issuers per request and stale authority for either issuer. Reject compact
  v1, v2 and identity-only envelopes at statement routes. Exercise
  global-identity mail with the new envelope. Replay across audiences,
  routes, raw queries and signature purposes. Preserve a pre-cutover
  delivered message's historical receipt and verification.
- Committed issuance before and after removal, a proof first presented after
  its deny was applied, credential expiry, stale feed at the cutoff, and
  previously admitted effects that finish. Include stream continuation and
  a write waiting on a lock.
- Repeated reads, exact idempotent replay with one effect/outbox and changed
  inputs refused, and one-use effects on retry. Check exact current evidence,
  wrong request digest and expiry. Test local admission before a minter
  denial with commit after it, and the resulting inability to use the
  delegation. Confirm an independent organisation-sponsored neighbour.
- Aborted and reordered transactions, missing or changed entries, duplicate
  entries, stale and replayed barriers, snapshot resync and era change. Reject
  a new era whose restore lacks an already-applied deny. Retain old denies
  and verify a tail from the signed snapshot commitment. Stop the statement
  signer, barrier signer and distribution independently. Check clock skew,
  timed idle barriers, recovery through a complete live point, public
  routes during issuer loss and jittered stream reconnects.
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
the same binding add no issuance. On an era change, every active binding may
need all its proofs reissued at once. The recovery capacity target is one
million active bindings within five minutes, about 3,334 signatures/s for
one proof or 6,667/s for two. At ten million bindings these figures are
33,334/s and 66,667/s. Pace and jitter retries under this load. Authority
stays unavailable for a binding until it has replacement evidence. Benchmark
the deployed signer, indexed reads and both feed transports rather than
extrapolating from raw signature operations.

Qualify the pilot's external watcher against the D2
[credential-free sentinel conformance cases](standing-organisation-records.md#credential-free-sentinel)
on the same registry build, including a watched private team's re-key and
loss of a verified feed prefix. The watcher alerts independently of worker
signing and serving authority.

| Implementation boundary | Acceptance |
|---|---|
| AWID issuance and signer | Consistent committed read, scoped ordinary and exact-request proofs, protected signer, issuance refusals and byte vectors. |
| AWID feed and public snapshot | Complete mutation inventory, atomic append, signed barriers, both feed reads, retention and scope-preserving resync. |
| Verifier SDK | Local validation and shared apply logic, published conformance for both transports, and issuer selection independent of the configured default. Exercise two exact domains with different issuers, an unavailable or conflicting discovery result, and a wrong-issuer response, with zero fallback. |
| aweb runtime and grants | Complete request inventory, local gates and typed refusal, owner-held grant/application facts, effect and stream tests. Show that the stream recheck reads registry standing only from the process's applied view, with no DB round trip for it. Show that grant revocation, app uninstall and workspace removal still end the affected stream before its next protected emission. Use event-driven local service facts or bounded DB reads, and measure and report any remaining DB recheck cost. Jitter each stream's first periodic authority recheck deadline independently across one recheck interval, within the existing freshness bounds. Test that streams opened together perform their first rechecks at different times within that interval. |
| Federation | Native interoperability between real standing issuers, exact trust bootstrap and recovery, and no request-time authority fetch. At E5, prove both directions refuse across the frozen boundary with no effect. For a later customer move, check retired, unknown and current addresses, including opt-in disclosure of a verified replacement. |
| Pilot, clients and registry deployment | Separate digest-pinned registry deploy at `https://api.awdid.org` in `servers`, named operations ownership, HA signer and feed recovery, and a first-deployment rehearsal for `awebai.org`. Verify client protocol selection, the per-process subscriber and readiness, and the exact DNS/controller bootstrap. Existing customers use the frozen service and source registry during E5. Verify side-by-side client and home isolation, fresh cohort admission, explicit use of the unchanged frozen identity, and old mail access. For the hosting-tree switch, qualify the service and client contract Juan selects in §7 before activation. |
| Scale and integration gate | Reproducible history, traffic, change, partition and recovery fixtures with stated hardware and measured limits. Run the E5 boundary against the real new registry and the pinned released registry and server. Test standing with the new client and frozen service with the released client. Verify issuance/feed loss, discovery failure and issuer isolation. Exercise fresh cohort onboarding, independent old and new sessions, and refusal of crossed client bindings. For a future customer move, apply §7's independent source-cut verification, exclusion and abort controls, full negative inventory check, source retirement and mail controls. |
