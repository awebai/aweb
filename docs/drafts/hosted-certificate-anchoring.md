# Hosted certificate anchoring, read-back, and expiry

Status: **design draft under adversarial review — not normative, no
implementation authorized.** Owned by id-bugs as the acceptance-2 half of the
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
(idempotent by `certificate_id`; conflicts mean already-registered). Scope:
**active certificates only.** Historical revoked certificates are not
backfilled — criterion 2 asks for current state, and alias reuse (many
historical holders of one alias) makes historical backfill a correctness
minefield the acceptance does not require. Rows that fail to register are
enumerated in the backfill report, not silently skipped.

Ordering: backfill before the removal protocol's commit step starts revoking
at the registry, so a revoke never targets an unregistered certificate.

## Expiry (exit-ladder rung 1) rides with this change

Per the threat-model rulings, certificate expiry is the committed first exit
from unbounded source-suppression, and it must land with certificate-format
work rather than alone. Design outline, to be specified fully before
implementation:

- Certificate format gains `expires_at` (v2 field). Verifiers: a certificate
  with `expires_at` in the past fails closed; a certificate without the field
  is legacy-valid during a declared transition window, after which issuers
  must set it and verifiers may warn on absence.
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
4. **Failure isolation at mint time**: if registry registration fails during
   hosted member creation, does creation fail (certificate authority
   unavailable) or succeed with a loud pending-registration state? The abfd
   precedent (publish loudly, don't fail the recorded membership, make the
   gap visible offline) suggests the latter, but a certificate is closer to
   the trust core than an encryption assertion — reviewer judgment wanted.
