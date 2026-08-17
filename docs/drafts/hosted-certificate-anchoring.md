# Hosted certificate anchoring, read-back, and expiry

Status: **design draft, review rounds 1-3 and the AC inventory
incorporated — not normative, no implementation authorized (Juan's hold
stands).** Round 1 verified the core decision
(existing registry routes accept hosted registration: no controller-key,
namespace, or addressless-member barrier exists in code) and broke the
original backfill scope; the reconciliation sweep, the expiry hard cutoff,
and the cloud-table disposition below are its required amendments.

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
`aweb-abfn` every server refreshes that list each minute. Restated after the
round-3 review broke the first version of this section:

- **Expiry lets verifiers reject without the list — once expiry exists.**
  Nothing in landed code has any expiry concept today; this is future v2
  behavior. Once `expires_at` lands, a verifier refuses an expired
  certificate outright, with no registry change required.
- **The list-size bound is a separate, explicit commitment — a filter,
  never a deletion.** Verifier-side expiry does NOT by itself stop the
  revocation list growing forever. This design therefore commits: after the
  legacy transition window closes, the default `list_revocations` response
  excludes certificates that are both revoked and expired. **Revocation rows
  are never deleted**: the exclusion is query-time only, because future
  acceptance-time and historical-verification work (this document's own
  eight-point table) needs "was this certificate in good standing at time T"
  answerable after expiry, and purging would foreclose it. The exclusion is
  safe for live enforcement precisely because verifiers hard-fail expired
  certificates on their own — absence from the default list cannot resurrect
  one — and it cannot apply to legacy no-expiry certificates, which is one
  more reason the transition window must actually close. With both halves, the enforcement-relevant
  revocation set caps at ~one validity window (90 days) of churn. Clients
  should additionally refresh incrementally (the route's `since` parameter
  exists; the Python client currently re-pulls fully — an implementation
  item).
- **Session grants fit only pure messaging workers.** Grants are scoped,
  expiring, revocable, and die with their issuing certificate under the
  landed enforcement — but they are hard-refused (403) outside mail/chat and
  roster reads, cannot claim tasks or hold locks, and act as their subject
  rather than appearing in the roster independently. So the guidance is
  narrower than first drafted: steer an ephemeral worker to a grant only when
  its job is messaging as its principal; any worker that must claim work,
  hold locks, or appear as itself needs full membership, and its anchoring
  cost is real — bounded by the expiry-plus-exclusion commitment above, not
  avoided.

### Roster visibility is a policy decision, made before implementation

Anchoring makes hosted team rosters (aliases and member keys — not
identities) readable wherever BYOT rosters already are. The registry's
existing team-visibility control is the knob; the **default for hosted teams
is Juan's decision and is required input before implementation starts**, not
an open question to resolve during it. (Supersedes the softer phrasing in
open question 1 below.)

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
original signed blob, which AC may not retain for superseded certificates —
not alias reuse: the registry's alias uniqueness is a partial index over
unrevoked rows only, so revoked rows sharing an alias are schema-supported.
Criterion 2 asks for current state; the sweep covers the security-relevant
remainder.

Ordering: backfill and sweep before the removal protocol's commit step starts
revoking at the registry, so a revoke never targets an unregistered
certificate.

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
   legitimate) — is **re-mint**: issue a fresh certificate for the same
   member key, register it, and refresh the projection, exactly the
   replace-key machinery that already exists. Without this gate, a member
   who did nothing wrong is locked out the moment existence becomes
   required.
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

## Expiry (exit-ladder rung 1) rides with this change

Per the threat-model rulings, certificate expiry is the committed first exit
from unbounded source-suppression, and it must land with certificate-format
work rather than alone. Design outline, to be specified fully before
implementation:

- Certificate format gains `expires_at` (v2 field). Verifiers: a certificate
  with `expires_at` in the past fails closed. A certificate without the field
  is legacy-valid only during a declared transition window of **one full
  validity cycle (90 days) from the date v2 issuance begins**, recorded as a
  concrete date in the SOT when implementation starts; after that date,
  absence is a **hard verification failure**, not a warning. An open-ended
  "may warn" would let any issuer keep the pre-expiry world alive
  indefinitely, which is no bound at all (review amendment). Because the
  format is issuer-controlled and signatures cover the full payload, a
  presenter cannot strip `expires_at` from an issued v2 certificate; the
  window governs issuers, not presenters.
- Issuance policy: hosted teams re-issue automatically ahead of expiry (the
  operator holds the controller key and the member roster); BYOT teams get a
  CLI re-issuance command and a doctor check that warns at
  expiry-minus-margin. Validity length is a policy knob for Juan; the draft
  proposes 90 days with re-issuance at 30 remaining, matching the E2E
  encryption-key assertion's existing lifetime shape.
- Expiry bounds suppression: a registry (or operator) freezing old state can
  keep a revoked-but-unexpired certificate alive only until `expires_at`.
  With revocation (60s, honest registry) and expiry (validity window,
  dishonest or frozen registry), both halves of the freshness story have
  bounds.
- Interplay with re-issuance and `agents.certificate_id`: re-issuing rotates
  the certificate id; the abfn projection refresh already tracks the presented
  certificate on every authenticated request, so enforcement follows
  re-issuance with no new machinery.

## Explicitly out of scope, mapped to the eight-point required shape

From the adversarial review of the verification-authority draft (task
`aweb-abfm`), the points this design does and does not cover:

| Required-shape point | Status |
| --- | --- |
| Write-side membership enforcement | Landed (`aweb-abfn`) |
| Complete, paginated revocations | Landed (`aweb-abfo`) |
| Bounded freshness, honestly stated | Landed (`aweb-abfp`, trust-model text) |
| Certificate availability to verifiers | **This design** (registry anchoring) |
| Expiry / suppression bound | **This design** (rung 1) |
| Signed envelope binding of team/cert IDs | Option-3 work, later |
| Non-backdatable acceptance-time proof | Removal ledger + receipts (`aweb-aauy` family), later |
| Team-key history for historical verification | Later; named gap |
| Custody as a separate claim | Unchanged; anchoring does not alter `verified_custodial` |

## Repo split and sequencing

- **OSS (id-bugs)**: certificate-format v2 with `expires_at`; verifier
  changes in `cli/go/awid` and the awid service validation; BYOT re-issuance
  command; doctor checks; SOT/docs updates; test vectors.
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

1. **Registry visibility of hosted rosters.** Anchoring makes hosted team
   membership readable wherever BYOT membership already is. Is the existing
   team-visibility control sufficient policy, and what should the default be
   for hosted teams?
2. **Expiry policy**: validity length and re-issuance margin (proposed 90/30
   days); whether the legacy transition window has a hard end date.
3. **Backfill authority**: run by the hosted operator offline, or exposed as
   a support-audited admin operation?
4. **Failure isolation at mint time** — resolved by review recommendation,
   adopted: creation does not hard-fail on a registry hiccup, but the gap is
   not a one-shot warning either. The member surfaces as `certificate:
   pending registration` through the same read-back this design builds
   (agent-status/members must never show "active" for an unregistered
   certificate); a background reconciliation sweep (the backfill logic run as
   an ongoing job) retries until it lands; and failure to self-heal within a
   bound tied to the certificate validity window escalates loudly, because an
   unregistered certificate is a silent enforcement gap, not a UX
   inconvenience.
5. **AC reader inventory** (open, assigned): the enumeration of AC-side
   consumers reading `cloud_agent_certificates` directly, and whether AC
   retains signed blobs for revoked certificates (decides the reconciliation
   sweep's fallback), is owned by the retirement instance and remains
   unanswered; asked by mail 2026-08-17.
