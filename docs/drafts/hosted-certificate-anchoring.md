# Hosted certificate anchoring and read-back

Status: **CONTRACT — implementation authorized (Juan, 2026-08-17: "yes go
ahead, also do the implementation"). The hosted roster-visibility default is
ruled: private by default, every existing team keeps its current value,
public is an explicit controller/admin opt-in, and the backfill never
resets visibility. Read-side enforcement is implemented, including the trusted
same-operator service credential used for private verification reads. The
registry-outage grace is adopted. Implementation is
tracked as an epic with per-repo tasks.** Sixteen adversarial review rounds
plus the AC inventory are incorporated. Certificate expiry, and everything
that existed only to serve it, was **removed from this design by owner
decision (Juan, 2026-08-17)**; it is not deferred, pending, or triggered —
it is not part of the architecture.

Review history in brief: round 1 verified the core decision (existing
registry routes accept hosted registration: no controller-key, namespace, or
addressless-member barrier exists in code) and broke the original backfill
scope; subsequent rounds shaped the reconciliation sweep, the cloud-table
disposition, and the visibility and availability sections.

Owned by id-bugs as the acceptance-2 half of the
`aweb-aaum.9` split recorded there on 2026-08-17; the removal-protocol half
(acceptance 1, `aweb-aauy`) is owned by the retirement instance in aweb-saas.
Their operation ledger is operational state and must not become a second
certificate source of truth; this design names the single authority both
build against.

## The three gaps this closes, and the one artifact they share

1. **aaum.9 criterion 2**: no read-only command can establish whether a hosted
   local member holds an active certificate. `aw team agent-status` honestly
   reports `unknown` because those certificates exist only in AC's
   `cloud_agent_certificates`, keyed by workspace.
2. **abfn's hosted limitation**: the landed revocation enforcement checks the
   admitting certificate against AWID registry revocations. Hosted local
   certificates never reach the registry, so enforcement is a no-op for
   exactly the members on app.aweb.ai.
3. **The trust model's option-3 target**: any reader verifying a local sender
   by certificate chain needs the member's certificate state to be
   verifier-readable.

All three are the same missing artifact: hosted local certificate state
anchored somewhere a verifier can read.

## The core design decision: hosted does what BYOT already does

A BYOT team's local-scope member certificates are **already registered in the
AWID registry** — registration, listing, revocation, and the freshly-landed
complete enumeration (`aweb-abfo`) and 60-second revocation caching
(`aweb-abfp`) all exist and are exercised by the tutorial path today. The
hosted service is the only issuer that mints certificates and never registers
them.

**Proposal: the hosted service registers every team certificate it mints at
the AWID registry, and revokes it there, exactly as a BYOT team controller
does.** The hosted operator already holds the team controller keys for hosted
teams, so no new authority is required; `register_team_certificate` and the
revoke route are existing, signed, idempotent-by-certificate-id operations.

What this buys, with no new protocol surface:

- **Read-back (aaum.9 crit 2)**: `aw team agent-status` and `aw id team
  members` read hosted local certificate state through the exact reads they
  already perform for BYOT teams. `Certificate: unknown` becomes a real
  answer.
- **Enforcement (abfn)**: the landed identity-only/grant/MCP revocation check
  works unchanged for hosted local members, within the existing 60-second
  bound. The removal protocol's commit step revokes at the registry, and no
  interim cloud-side revocation fact is needed at all — which keeps the
  retirement ledger purely operational, per the agreed boundary.
- **Option 3 groundwork**: certificate existence and revocation state become
  registry facts for every member class. (Full option 3 still needs the
  blob-fetch path, team-key history, and acceptance-time anchoring — tracked
  below, deliberately out of this design's scope.)

### What this does and does not change about local identities

Registering a certificate registers a **membership fact**, not an identity.
The negative guarantee is part of this contract: anchoring a local member's
certificate must not confer any global property on the identity — no
`did:aw`, no address, no reachability, no resolvability as an identity.
Local identities keep no registry row *as identities*; global identities are
unchanged. This is already how the registry routes behave (round-1 review:
addressless local members pass registration with zero address validation, and
BYOT teams register local-scope member certificates today — the tutorial pair
exercises it live); the contract states it so it cannot drift. The
message-trust split is also unchanged: global senders verify against public
identity records, local senders against the live roster; this design adds
membership/revocation state, not identity state.

### Churn: local members are many and short-lived

Local agents are spawned and retired constantly; anchoring every certificate
means per-team revocation lists grow with every retirement, and since
`aweb-abfn` every server refreshes that list each minute. What is actually
known about the list rests on two facts, neither of which is a size
ceiling:

- **The resident-identities model keeps membership churn small — where it
  is used.** Ephemeral workers served as session grants create no
  certificates and no revocations, so for resident-based teams revocation
  rows accrue only on real membership turnover. Stated honestly against
  current practice, though: today's grants cover only pure-messaging
  workers, and teams that spawn full-member task-scoped instances (this
  project's own spawn/retire-instance pattern — every reviewer and
  developer instance is a full certificate, revoked at retirement) make
  worker turnover BE membership turnover. For such teams the revocation
  list grows monotonically with no stated ceiling or retention policy —
  slowly, but forever. The honest bound today is "growth proportional to
  full-member turnover, unbounded over a team's life"; shrinking it means
  either widening grant scopes so coordinated workers stop being members
  (future design) or a retention policy, neither of which this contract
  commits to.
- **Complete enumeration scales on the read side.** The `aweb-abfo` cursor
  pagination handles arbitrarily large lists correctly. The Python verifier
  deliberately re-pulls the complete paginated revocation set: `revoked_at`
  is a transaction-start timestamp, not a commit-order cursor, so an
  incremental high-water mark can miss a late commit after a row-lock wait.
  Incremental refresh remains deferred until the protocol exposes a durable
  monotonic resume cursor. This is a claim about clients handling the list,
  not about the list staying small.
- **Session grants fit only pure messaging workers — and this is the
  resident-identities design, not an accident.** The prior product design
  (strategy/product/2026-08-12-resident-identities-and-session-grants.md)
  defines the model: one durable resident identity per role is rostered and
  (under this design) AWID-anchored; concurrent session grants act *as* it;
  external parties see one principal and worker provenance stays private;
  grants make no fencing claim — fencing belongs to the managed-mode
  architecture. Worker retirement is grant-revoke-plus-TTL and never the
  `aweb-aauy` principal retirement; principal retirement's commit
  invalidates every outstanding grant through the issuing-certificate
  relation the landed `aweb-abfn` check already provides. The current grant
  scope is messaging-only plus roster reads; wider scopes (the original
  design illustratively mentioned task claiming) are future design. Any
  worker that must claim work, hold locks, or appear as itself needs full
  membership.

### Roster visibility: read enforcement is implemented

The registry stores controller-set visibility and now enforces it across team
metadata, domain enumeration, certificate history, member lookup, and
revocations. Public teams remain anonymously readable. Private-team reads
require a controller or unrevoked-member path signature, or the configured
trusted same-operator service credential. That credential is a confidential
private-roster read capability used by server-side verification and
reconciliation; it is not merely a rate-limit exemption, grants no write
authority, and the registry client sends it only to its exact configured home
registry. An unconfigured service must sign with a same-team key or fail the
private read rather than bypass visibility. BYOT CLI reads sign with available
team credentials.

The default is **ruled (Juan, 2026-08-17): private by default**. Every existing
team keeps its current value, public is an explicit controller/admin opt-in,
and the backfill never resets visibility. The resident-identities model keeps
this coherent at any visibility: roster readers see one resident member per
role, never its session-grant workers, whose provenance is private by design.

### What happens to `cloud_agent_certificates`

The registry becomes the only certificate authority; the cloud table becomes
a **non-authoritative cache, never consulted for verification verdicts**. Its
`revoked_at` is written in the same commit step as the registry revoke —
ordered and never eventually-consistent, though not a literal single
transaction across two services — so it cannot silently disagree with the
registry for its remaining operational readers. The AC-side inventory of
those readers — dashboard, support tooling, any auth overlay reading the
table directly — is owned by the retirement instance, under one rule: no
consumer may report certificate state the registry contradicts; each reader
is either repointed at the registry or documented as reading the synced
cache. Leaving any reader on an unsynced table would recreate the second
source of truth this design exists to remove.

### Rejected alternatives

- **A new AC read surface** (cloud certificate status endpoint + CLI client):
  creates a second authority with its own freshness, enumeration, and
  rate-limit story — everything abfo/abfp just built would need rebuilding,
  and verification would fork by custody. Rejected on the one-source
  principle.
- **Anchoring digests only**: the registry already stores full certificate
  metadata for BYOT local members; hosted members are not more private by
  policy. If roster privacy is wanted, it is the registry's existing team
  visibility control, applied uniformly — not a parallel format.

## Migration: existing hosted members

Backfill: for each live row in `cloud_agent_certificates`, the hosted service
registers the certificate at the registry under the team controller key
(idempotent by `certificate_id`; conflicts mean already-registered). Rows that
fail to register are enumerated in the backfill report, not silently skipped.

**Reconciliation sweep (review amendment — this closes a traced hole).** A
certificate that was never registered can never appear in the registry's
revocation set, so it passes the revocation check *by omission*: a hosted
member revoked at AC before this design lands, whose `agents` row is still
live, would be protected by neither enforcement path, indefinitely.

The AC inventory (aweb-aaum.9, 2026-08-17) showed the sweep's predicate is
not locally computable: `cloud_agent_certificates` has no certificate-ID
column, no registration status, and no revoked marker — a present row may be
active, registry-revoked, or never registered, indistinguishably — and AC
carries a second uncontrolled blob store (`aweb.agents.team_cert_blob`) with
no consistency constraint. The sweep is therefore **registry-classified**:
decode the certificate ID from every stored blob (both stores), classify each
against AWID (registered-active / registered-revoked / never-registered),
then per class: registered rows are left (or cache-synced); never-registered
rows with a valid blob are registered (then revoked if their member is
retired); rows whose blob is missing or unusable get their projection deleted
— blobs are not reliably retained after revocation, so the deletion fallback
is required, not optional. Each remediation is reported. This population is
bounded and enumerable; it is exactly the split-state class aaum.9 describes.

Historical revoked certificates beyond that population are not backfilled.
The honest reason is **data availability** — registration requires the
original signed blob, which AC may not retain for replaced certificates —
not alias reuse: the registry's alias uniqueness is a partial index over
unrevoked rows only, so revoked rows sharing an alias are schema-supported.
Criterion 2 asks for current state; the sweep covers the security-relevant
remainder.

Ordering: backfill and sweep before the removal protocol's commit step starts
revoking at the registry, so a revoke never targets an unregistered
certificate.

## Registry availability posture (from operational history)

The team's 2026-06 incident diary recorded weeks of intermittent
"AWID registry unavailable" 503s on the coordination path. Its own final
entry reclassified much of that pain: blanket exception-to-503 handling in
the aweb auth paths converted stale-connection/DNS client faults into
"registry unavailable", since narrowed to distinct error classes; the
remainder were genuine per-request transients with green health. Two
structural changes since then bound the exposure: registry reads on auth
paths ride the Redis-backed cache (fresh 60s, stale-while-revalidate to
120s, cache survives restarts), so a transient blip during a cache window
does not surface at all and a failed background refresh serves stale with a
warning naming the team, data age, and failure; error classes are distinct.
This design adds **no new
per-request registry calls**: mint-time registration is non-blocking
(pending state), commit-time revocation is ledger-retryable, and enforcement
widens which requests consult the *cached* state, not how often the network
is touched.

The residual: a sustained registry outage longer than 120 seconds turns into
503s for team-context messaging — the posture the certificate path has
always had, now covering more requests. **ADOPTED (Juan, 2026-08-17)**: the
bounded outage grace — on refresh failure, serve the last-known revocation
set up to a stated window (15 minutes), loudly logged, then fail closed.
During a registry outage messaging stays up; the worst case is a
certificate revoked mid-outage remaining effective up to the grace window.
For clarity of mechanics (confirmed at adoption): the revocation check is a
local set-membership test on the aweb server against a Redis-cached copy
fetched server-to-server once per team per minute; the list carries only
certificate UUIDs and timestamps, and clients never receive it — the
pull-and-cache CRL shape is deliberate, chosen over per-check registry
queries which would be chattier, harder-coupled, and leak usage patterns to
the registry. **The grace is implemented** (epic task aweb-abfs.3), and it is
not a tunable parameter (round-8 review finding, honored in the build): the
cache client gained a revocation-specific retention tier — revocation
entries carry their fetch timestamp and are retained fifteen minutes beyond
freshness, with fresh/stale/grace decided on data age, never on Redis
expiry — and both the background-refresh and foreground-fetch failure paths
log at warning level with the team, the served data's age, and the error,
replacing the previously silent debug handler. Past fifteen minutes of age
the read fails closed exactly as before; the bound is a constant pinned by
test, with no configuration knob, and no other cache tier's retention
widened. The grace trades a bounded revocation delay during outages for
messaging availability; it sits inside the already-ruled bounded-staleness
doctrine, and the operational history above is the argument for it.

## Conditions the AC inventory adds to "every mint registers"

From the retirement instance's authorized read of AC (evidence on
aweb-aaum.9, 2026-08-17):

1. **Team registration is a precondition.** Controller key material always
   exists at mint, but the team's own registry registration is a separate
   sequencing condition; certificate registration requires the team to be
   registered first (or atomically ensured).
2. **The `team-service` certificate class must be classified.** The Library
   hosted-auth controller branch mints fresh, unregistered, non-roster
   certificates. Default position: they register like any other certificate;
   if a reason exists to keep them off-registry it must be argued explicitly
   and they get their own named class and verification rule.
3. **Verification eventually requires registration — staged, with an
   emptiness gate.** AC's own bridge (like the pre-abfn OSS paths) passes
   unregistered certificates by omission: it checks signature plus
   not-in-revocations, never existence. End state on both sides: a
   certificate that is not registered fails verification. Staging: it cannot
   precede backfill and sweep, and — round-4 amendment — "have run" is not
   sufficient: existence-required verification may activate **only once the
   backfill's failure enumeration is empty or every enumerated failure has an
   individual remediation completed**. The named remedy for the hardest case
   — a legitimate, active member whose signed blob is lost or corrupted, who
   can neither be registered (no blob to submit) nor deleted (they are
   legitimate) — is the **fresh-certificate re-issuance operation**: sign a
   fresh certificate for the *same* member key, register it, and refresh
   the projection. **Two cases, corrected after the coordinator's post-land
   finding and settled by what shipped** (`aw id team reissue-cert`,
   aweb-abfs.4, landed `ebf87401`): where the lost-blob certificate was
   never registered, the fresh registration is direct and no alias conflict
   can arise; where the registry *does* hold a row for that alias — which
   `docs/awid-sot.md` explicitly provides for as a registered, metadata-only
   pre-blob row with no stored blob — the operation revokes that row and
   registers the fresh certificate after, in that order, because the
   registry permits one unrevoked row per `(team_uuid, alias)` and its
   insert-only registration route answers `409 Alias already active in
   team`. The earlier claim that no conflict could arise "because a lost-blob
   certificate was never registered" was false for the BYOT metadata-row
   case and is withdrawn. This is exceptional, controller-authorized blob
   recovery — not renewal, supersession, or expiry, all of which remain
   removed from this architecture. Hosted teams need the equivalent operation
   alongside BYOT; the BYOT half is an OSS deliverable in the repo split
   (done). It is deliberately NOT the
   replace-key machinery, which structurally requires a key change at both
   client and server layers and exists for lost or compromised keys — a
   different situation than a lost certificate blob. Without this gate, a member
   who did nothing wrong is locked out the moment existence becomes
   required. **One non-member object is classified here** (coordinator
   ruling, 2026-08-17), because strict verification must not silently bless
   it: the Library binding's per-material-load `team-service` object presents
   a pseudo-membership certificate that is non-roster, non-durable, and not
   registered — it is not a member and must not be registered on every load.
   The live Library provider is therefore unsupported while the strict flag
   is on, until a separately authorized design replaces the per-load
   certificate with an explicit controller-auth/service-delegation rule or a
   durable registered service member. Absent `LIBRARY_BASE_URL` the static
   stub is selected, which is the default; the production activation
   checklist must confirm that. This is a classification only — it authorizes
   no Library work, which remains paused.
4. **The W ≠ A invariant.** AC's `ensure_stored_agent_team_certificate`
   currently keys the cloud table by agent UUID as though it were the
   workspace UUID; hosted workspace and agent UUIDs are decoupled. The
   invariant this contract requires: one blob-derived certificate ID carried
   consistently through workspace `W`, projected agent `A`, and AWID. Fixing
   that helper is a prerequisite before the mapping is trusted.
5. **Migration-017 alignment.** AC paths that create or refresh agent
   projections outside the OSS connect flow (direct-connect, remint, generic
   projection writes) must set `agents.certificate_id`, or abfn enforcement
   stays blind for members provisioned through them.

## Explicitly out of scope, mapped to the eight-point required shape

From the adversarial review of the verification-authority draft (task
`aweb-abfm`), the points this design does and does not cover:

| Required-shape point | Status |
| --- | --- |
| Write-side membership enforcement | Landed (`aweb-abfn`) |
| Complete, paginated revocations | Landed (`aweb-abfo`) |
| Bounded freshness, honestly stated | Landed (`aweb-abfp`, trust-model text) |
| Certificate availability to verifiers | **This design** (registry anchoring) |
| Expiry / suppression bound | Removed by owner decision (2026-08-17) |
| Signed envelope binding of team/cert IDs | Option-3 work, later |
| Non-backdatable acceptance-time proof | Removal ledger + receipts (`aweb-aauy` family), later |
| Team-key history for historical verification | Later; named gap |
| Custody as a separate claim | Unchanged; anchoring does not alter `verified_custodial` |

## Repo split and sequencing

- **OSS (id-bugs)**: the outage-grace retention tier and loud
  refresh-failure logging in the cached registry client (done, aweb-abfs.3); the
  fresh-certificate re-issuance operation (blob-lost
  remediation) (done, aweb-abfs.4); read-side
  visibility enforcement on the registry's team/certificate/member/
  revocation reads for private teams (done, aweb-abfs.1), with CLI signed
  reads following (aweb-abfs.2); staged existence-required verification
  (done, aweb-abfs.5, default off); doctor checks; SOT/docs updates; test
  vectors.
- **AC (retirement instance)**: mint-time registration, the backfill, and
  wiring the removal protocol's commit to the registry revoke. These ride
  their prepare/commit implementation; the interface between us is exactly
  "the registry is the certificate authority; the ledger is operational
  state."
- Cross-repo review and integration through the coordinator; production
  backfill and any policy on existing members need Juan's approval, same as
  the removal protocol's own gate. The bulk-hosted-operations freeze stays
  until the aaum.9 family lands.

## Open questions for review and for Juan

1. **Registry visibility of hosted rosters** — ruled by Juan on
   2026-08-17: private by default, existing values preserved, public by
   explicit opt-in, backfill never resets; the existing control is *not*
   sufficient until read-side enforcement is built (see the visibility
   section), and that build is an epic task. Retained here as the record
   that the question is closed, not open.
2. **Backfill authority**: run by the hosted operator offline, or exposed as
   a support-audited admin operation?
3. **Failure isolation at mint time** — resolved by review recommendation,
   adopted: creation does not hard-fail on a registry hiccup, but the gap is
   not a one-shot warning either. The member surfaces as `certificate:
   pending registration` through the same read-back this design builds
   (agent-status/members must never show "active" for an unregistered
   certificate); a background reconciliation sweep (the backfill logic run as
   an ongoing job) retries until it lands; and failure to self-heal within a
   fixed operational bound (proposed: three consecutive failed
   reconciliation cycles, or 24 hours, whichever comes first) escalates
   loudly, because an unregistered certificate is a silent enforcement gap,
   not a UX inconvenience.
4. **AC reader inventory** — answered 2026-08-17 by the retirement
   instance's authorized read (evidence on `aweb-aaum.9`): direct
   readers/writers enumerated; signed blobs are NOT reliably retained after
   revocation (hence the sweep's required deletion fallback); and the
   findings are incorporated above ("Conditions the AC inventory adds" and
   the registry-classified sweep). Retained here as the record that the
   question is closed, not open.
