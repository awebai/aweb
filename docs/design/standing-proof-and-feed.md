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
domain and delegation rules. Verify the binding from the authority for that
exact domain to the standing and feed signer before pinning it. Public
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

Clients select the serving contract from trusted domain and service
configuration before they sign. They use the released contract for the
frozen service and standing for E5. A client can support both contracts.
E5's native serving routes accept only the request-bound protocol in §2.

**E5 launch scope.** Serve `awebai.org` using standing
and leave cross-federation with the frozen `aweb.ai` disabled in both
directions. Give the initiating client a typed unsupported-peer refusal
when trusted discovery identifies a released-only peer. An unknown or
unreachable authority retains the authority-unavailable refusal. Apply the
same no-effect rule at ingress. This preserves the fail-closed rule and zero
request-time authority lookups. Native federation between admitted
standing issuers remains part of OSS conformance.

The alternative of exchanging traffic at launch has separate requirements
in each direction.

- **E5 sender to frozen recipient.** The frozen receiver expects the
  released holder-signed federation artifact and obtains sender authority
  through the [released registry reads](../awid-sot.md#addresses).
  The new registry would need to implement the exact read contract used by
  the frozen binary, including namespace, address, key and identity-log
  resolution, and certificate status, member lookup, revocations and team
  key reads wherever that binary uses them. Inventory the actual routes,
  fields and refusals against that pinned binary. All reads use the same
  committed authoritative state as the feed and keep their existing
  authorization. Private team reads cannot be opened to anonymous or
  foreign service-token callers. The sender would also need to sign the
  exact released destination artifact alongside the standing-bound
  submission to E5. E5 would relay those bytes only to the pinned legacy
  destination. Keeping the reads alone enables neither an arbitrary
  signature conversion nor traffic in the reverse direction.
- **Frozen sender to E5 recipient.** The frozen issuer supplies neither
  standing nor an authenticated feed. A released federation artifact alone
  cannot qualify at a standing route. An explicit compatibility option
  would require a separate ingress adapter for the exact allowlisted
  legacy peer, limited to released message delivery. It would verify the
  original destination-bound artifact and use current authoritative
  online reads of the legacy registry. It would have to fail closed on
  unavailable evidence, bound evidence age at admission, preserve recipient
  delivery policy and replay settlement, and confer no session, team, app
  or delegation authority. That path would incur online authority reads
  and would have no 30-second applied-feed guarantee. Native E5 routes
  would keep both guarantees. Any such adapter and released read surface
  need explicit approval and bidirectional tests before enablement.

After E5, a separately approved additive standing issuer at the existing
registry could keep released reads for its current service while enabling
native proofs and feed validation for upgraded peers. Both serving services
would still need compatible federation protocol support to exchange mail.
For E5, `api.awid.ai` and its frozen clients keep their released contract.

## 7. First deployment and later origin moves

On 2026-11-28 Juan authorised a second AWID registry for E5, at its own
origin, with `_awid.awebai.org` pointing there and `api.awid.ai` unchanged
for frozen `aweb.ai`. Use the normal landing and deploy gates. The operator
records the approved production origin and change window before deployment
and DNS changes.

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
custody and access policy. Provision their trust binding through the
domain's authorised controller. They confer no controller or membership
authority. The pilot's custody plan keeps the `awebai.org` root and team
controller keys outside the hosted service. Bootstrap the first chain at
the new registry with those authorities, using the exact staged admin
identity and team binding. Private reads retain their existing authorization.
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

### Moving an existing origin

Moving an application's delivery origin and transferring a namespace's
registry authority are different operations. A delivery move can retain
its registry if that issuer supports the target protocol. Transferring a
namespace while keeping its identities requires a separately approved
transfer protocol. A DNS change publishes the selected authority. The
transfer must prove continuity of that authority and its facts.

The future transfer must fence source writes and issuance, export an
authenticated final cut, and verify it at the destination before changing
DNS and verifier pins. Preserve stable DIDs, signed chain and key history,
controller and team generations, certificate status, ancestor cutoffs and
revocations, and address assignments and reachability. Carry surviving
denies and document how existing proofs stop being accepted at the old
authority boundary. Make any old discovery state read-only through the
transition and exclude stale writers and issuers. The grant owner must
account for its own delegation state or explicitly require new grants.
Prove the same current unrevoked identity works after the move, a revoked
one cannot revive, and a historical message retains its original evidence.

### First migration after E5

The first cohort is the agents currently on `juan.aweb.ai` and the OATS
team. Rehearse this as a coordinated move when E5 is ready. The migration
owner inventories canonical namespaces and teams, current holders, address
and routing bindings, service grants, client homes and mail state. For
each domain or team, identify its controller, who remains on the old
service, and who can authorise a move. An agent cohort cannot move an
entire namespace or team on its own. Any remaining dependency must have
an authorised destination or be resolved before cutover.

1. **Identities and addresses.** Re-establish the moving namespace with
   its authorised controller and import the authenticated final cut.
   Keep each global agent's stable DID and current signing key, with
   verifiable history and cutoffs. Preserve its address assignment and
   change the delivery origin with the signed update required by the
   address and routing authorities.
   Prove the same DID owns the address after the update. A team-local
   identity has no portable global DID or public address. Inventory its
   existing team and key, and carry it only with verified continuity of
   that team binding. A newly admitted local identity is an explicit
   enrolment and must be recorded separately.
2. **Teams and holders.** Re-register the moved teams' authorised keys and
   certificates against the imported history, preserving valid roles and
   membership scope. Any replacement certificate must be signed by the
   authorised team controller and bound to the exact holder, with old
   versions retired. Carry denials and key versions before issuing
   statements. Rebind agent homes and workspaces and settle service grants
   with their owners. Refuse a previously removed member and a misbound
   grant in the rehearsal.
3. **Mail and switch.** Fence admissions and sends at the old scope and
   drain or reconcile accepted deliveries and outbox jobs. Import or
   expose authenticated read-only history under the same recipient
   entitlement. Preserve original signed artifacts, conversation IDs,
   receipt and verification state, and ciphertext and key references.
   Keep decryption custody with its holder. Reconcile all accepted message
   IDs and outstanding retries before opening the new inbox. Settle an
   accepted old send against its original receipt. An unsent delivery
   needs a new destination-bound request once its route has changed.
   Verify old mail remains readable with its original verification treatment.
   A reply to a migrated participant uses the same conversation and
   current verified route. A participant still on the frozen service remains
   outside E5 federation. Report the unavailable reply path to the holder.

Run the rehearsal against a real source and destination. Require matching
identity, address, team and mail inventories at the activation boundary,
a valid moved sender, an independently refused revoked member, and an
exact mail retry with a single receipt and effect. Keep old writes fenced
after activation. The first migration is the next milestone after E5
readiness, with its own acceptance and change window.

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

| Implementation boundary | Acceptance |
|---|---|
| AWID issuance and signer | Consistent committed read, scoped ordinary and exact-request proofs, protected signer, issuance refusals and byte vectors. |
| AWID feed and public snapshot | Complete mutation inventory, atomic append, signed barriers, both feed reads, retention and scope-preserving resync. |
| Verifier SDK | Local validation and shared apply logic, published conformance for both transports, and issuer selection independent of the configured default. Exercise two exact domains with different issuers, an unavailable or conflicting discovery result, and a wrong-issuer response, with zero fallback. |
| aweb runtime and grants | Complete request inventory, local gates and typed refusal, owner-held grant/application facts, effect and stream tests. |
| Federation | Native interoperability between real standing issuers, exact trust bootstrap and recovery, and no request-time authority fetch. At E5, prove both directions refuse across the frozen boundary with no effect. A separately approved legacy path would require the exact frozen binary, compatible read surface and isolated delivery adapter, including tests for private-read restrictions, signature purpose, exact retry settlement and outages scoped to that path. |
| Pilot, clients and registry deployment | Separate digest-pinned registry deploy in `servers`, named operations ownership, HA signer and feed recovery, and a first-deployment rehearsal for `awebai.org`. Verify client protocol selection, the per-process subscriber and readiness, and the exact DNS/controller bootstrap. Keep the frozen service and registry on their released contract. Hand off the first-cohort inventory and transfer rehearsal for the migration immediately after E5. |
| Scale and integration gate | Reproducible history, traffic, change, partition and recovery fixtures with stated hardware and measured limits. Run the E5 boundary against the real new registry and the pinned released registry and server. Test both standing and frozen serving paths with the same client and verify issuance/feed loss, discovery failure and issuer isolation. Qualify the first migration separately with the identity, address, team and mail controls in §7. |
