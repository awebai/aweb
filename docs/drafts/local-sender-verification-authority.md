# Local-sender verification authority

Status: **resolved — Juan ruled 2026-08-17; the rulings are normative in
[trust-model.md](../trust-model.md) ("Threat-model rulings"). This file is the
record of the analysis, its adversarial correction, and the path to the
ruling.** Partial-service compromise is in scope (Option 2 as drafted is
permanently dead); the suppression residual is accepted as a named operator
trust assumption with a committed exit ladder (expiry → chained revocation
log → witnessing). Full review findings on task `aweb-abfm`.

## Adversarial review outcome (2026-08-17)

The review broke the recommendation, and the author verified its decisive
factual claims against the code. What broke:

1. **The write-side membership premise is false.** Identity-only messaging
   auth (`server/src/aweb/identity_auth_deps.py:185-201`) derives team/alias
   from the live `agents` projection by key possession alone — no certificate,
   no revocation check. A revoked local member whose projection survives (the
   aweb-aaum.9 split-state family) can keep sending under its team alias by
   omitting the certificate header. Identity grants share the gap. Filed as
   its own bug.
2. **"No independent security" conflated full and partial compromise.** The
   fresh roster read is a real cross-check against a compromised message
   store or ingest component when the roster component is honest. Option 2
   removes that without replacing it. The claim holds only if the server is
   modeled as a single indivisible adversary — which is a threat-model choice
   that belongs to Juan, not an implementation fact.
3. **Option 3 cannot prove membership-at-send with today's artifacts.**
   Certificates carry `issued_at` but no expiry, message timestamps are
   sender-controlled, so a revoked member can backdate. Historical membership
   needs a non-backdatable acceptance-time anchor (service-signed receipt or
   witnessed log).
4. **The "only cert transport is missing" claim was materially too small.**
   No public certificate-blob fetch; team-key rotation overwrites
   `teams.team_did_key` with no history; the revocation route truncates at
   the oldest 1000 rows with no pagination while clients consume it as
   complete (filed as its own bug); no end-to-end freshness bound exists or
   can exist without witnessing/transparency.
5. **Replay/downgrade were undefined**: the signed envelope binds no team ID
   or certificate digest, so a carried certificate could be substituted or
   stripped.

Standing ruling until Juan decides otherwise: **Option 1** (status quo,
documented; instrument standardization already on main at `93c308fa`). Option
2 must not ship as `verified`; if ever built it needs a distinct
`verified_server_attested` status and must still fail on roster mismatch when
the reader can obtain the roster. Option 3 remains the target *direction*
only as the larger protocol in the review's "required shape" list: current
write-side enforcement fixed first, signed envelope binding of
team/certificate/delegation, non-backdatable acceptance-time proof, public
immutable certificate blobs, namespace-authorized team-key history, complete
paginated revocations, an honest freshness model, and custody preserved as a
separate claim.

Decisions that are Juan's, not a coordinator's: (a) whether partial-service
compromise is in scope of the trust model; (b) whether an unbounded
source-suppression residual is acceptable or witnessing/transparency is
required.

The sections below are the original analysis, kept intact as the record the
review examined. Where a claim was broken, the outcome above supersedes it.

## Why this document exists

While fixing aweb-abfc (`[verification stale]` on every tutorial message), the
root cause turned out not to be a bug in verification itself but an
architectural wrinkle the bug exposed: **the verification verdict for a
local-scope sender depends on the reader's credential**, and in one command's
case on which command the reader happened to run. The command-dependence was
fixed (main `93c308fa`); the reader-credential dependence remains, and this
document assesses whether it is the right architecture.

The principle under evaluation, as stated by Juan:

> Validation is a matter of what kind of identity you are, not of what command
> you are running.

## The two planes

Two different things are both called "auth/verification":

1. **Request authentication** — who is calling this API. Every request is
   signed by the identity signing key (DIDKey scheme). The team certificate
   never signs anything; when presented, it rides alongside the DIDKey
   signature as membership context (`X-AWID-Team-Certificate`).
2. **Message trust** — whether a reader should believe the claimed sender wrote
   a stored message. This is the plane that renders `verified` /
   `verification_stale` / `identity_mismatch`.

The team certificate therefore does not replace the identity. Per the
authority graph in [trust-model.md](../trust-model.md): the identity signing
key "signs messages and requests"; the team controller key "signs/revokes
membership certificates that bind member identity keys". A certificate is a
fact signed by a *different* authority: "did:key K is member alias A of team T,
scope S". Its distinctive power on the messaging plane is authorization: it
admits the holder to team surfaces, including **reading the team roster**.
`get_messaging_auth` (server/src/aweb/identity_auth_deps.py:153) converges
grant, certificate, and bare-identity auth into one `MessagingAuth`; the
mailbox is DID-scoped under all three.

## Verification is signature plus binding, and the binding authority differs by identity kind

A valid signature proves "someone holding key K wrote this". A verdict of
`verified` must additionally bind K to the claimed sender *name*. Who holds
that binding:

- **Global identity**: AWID — DID log, address rows, DNS-anchored controller,
  TOFU pins. Public. Any reader can consult it with no team credential. For
  global senders, "having an id is all you need to be verified" is true.
- **Local identity**: per
  [identity-messaging-contract.md](../identity-messaging-contract.md), a local
  identity is "`did:key` only, no AWID row, no `did:aw`". The only place the
  alias-to-key binding exists is the team roster, and
  [trust-model.md](../trust-model.md) (TOFU section) says: "Local single-team
  identities skip persistent global TOFU pinning. Their current key is
  refreshed against the live team roster."

Consequence: verifying a local sender requires roster access; roster access
requires membership. It is the **reader** that needs the certificate, not the
sender that needs one to be verifiable. A reader without roster access gets
`verification_stale` — exactly its defined meaning ("signature may be valid,
but authoritative continuity/freshness could not be completed"), and exactly
the reader-credential dependence under evaluation.

## What the server already enforces at ingest

Verified in server/src/aweb/routes/messages.py (three send paths, lines
489-490, 807, 1071-1072 at main `93c308fa`): **`from_did` must match the
authenticated sender**, and `from_alias` is server-derived from the agents row
for that did — never caller-supplied. Delivery policy (`inbound_mode:
team_and_contacts`) additionally gates non-members at delivery time, and team
surfaces (roster, coordination) are certificate-gated.

So the participation half of the principle — an identity that cannot prove
membership must not be able to inject messages under a roster alias — is
already enforced at the write side.

## The finding

**For local identities, the reader-side roster re-check adds no independent
security.** The same aweb server authenticated the send, derived the stored
alias, and serves the roster the reader consults. Reader-side and server-side
verification bottom out in the same single trust root. The read-time roster
check's genuine value is:

- **freshness** — is this sender still the current holder of that alias
  (matters under alias reuse: many historical "alices"), and
- defense against server **bugs** (inconsistent stored state),

but not defense against a malicious or compromised server, which could serve a
matching forged roster alongside forged messages. For global identities the
reader-side check *is* an independent-authority check (AWID + DNS + pins +
DID-log anti-rollback); for local identities it is a consistency check wearing
the same vocabulary.

The current architecture therefore violates the principle in exactly one
place: local-sender verdicts are a function of the reader's roster access.

## Options

### Option 1 — status quo, documented

Keep verdicts as a function of (sender kind, reader's access to the binding
authority). Standardize the instrument (done in `93c308fa`) and add one honest
sentence to the trust model. Cheapest; keeps the wrinkle.

### Option 2 — server-attested verification for local senders

Since the server already authenticates `from_did` at ingest and is the
roster's only home, a reader treats a local sender as verified when the
message signature checks against the stored `from_did`; the roster read only
*elevates* to "current member" or flags drift. Local-sender verdicts become
reader-independent. Epistemically honest: "verified" for a local sender openly
means "authenticated by the team's server", which is already the reality.
Cost: it collapses any pretense of reader-side independence for local ids.

### Option 3 — verify local senders by their certificate chain (proposed target)

The team controller's public key is public (AWID `teams.team_did_key`,
anchored through the namespace controller to DNS), and certificate revocation
events are AWID authority per the identity-messaging contract's own authority
table. If the sender's membership certificate travels with the envelope (or is
fetchable at read time), then **any** reader — member or not, certificated or
not — can verify a local sender:

1. certificate signature verifies under the team controller key fetched from
   public AWID;
2. certificate binds the claimed alias to the message's `did:key`;
3. certificate is not revoked (AWID revocation events).

Local-sender validation becomes purely a function of what the *sender* is —
the principle satisfied exactly — and independent of the aweb server. The
roster demotes to a liveness/convenience layer instead of a trust root. The
verification primitives already exist (`VerifyTeamCertificate`, team keys and
revocations in AWID); the missing piece is carrying or fetching the sender's
certificate at read time.

Two structural convergences:

- **aaum.9.** Hosted local members' certificates live in
  `cloud_agent_certificates`, invisible to the registry — which is both why
  hosted retirement has no read-back (aaum.9 criterion 2) and why Option 3
  cannot cover hosted local members today. Publicly (or team-verifiably)
  anchored certificate state for hosted local members closes both gaps with
  one artifact.
- **Alias reuse.** A reused alias means a revoked certificate for the old
  holder and a fresh one for the new. Historical mail verifies against the
  certificate that covered it at send time, not against whoever holds the
  alias today — which the live-roster check gets wrong by construction.

## Recommendation

1. Write the principle into trust-model.md as normative: *a sender's
   verification verdict is a function of the sender's identity kind and the
   authority for its name binding, never of the reader's command, and — for
   the target architecture — never of the reader's credential.*
2. Near term: Option 2 (small, removes the reader-credential dependence,
   honest about the trust root).
3. Target: Option 3, folded into the aaum.9 / certificate-read-back design
   where it structurally belongs, with alias-epoch handling aligned to the
   stable-identifier retirement design.

## Known attack surfaces for review (please try to break these)

- **Option 2's core claim**: is there any concrete scenario where the
  read-time roster check catches a *malicious* (not merely buggy) server that
  Option 2 would miss? If yes, the "no independent security" claim fails.
- **Option 3 revocation freshness**: a revoked member whose certificate still
  verifies at readers that have not seen the revocation. What staleness window
  is acceptable, and who bounds it? (Compare the federation 60-second cohort
  ceiling and its explicit non-SLA residual.)
- **Certificate replay across teams/scopes**: can a valid certificate for
  team T be presented to verify a message in a conversation the reader
  attributes to team T'?
- **Envelope bloat and downgrade**: if certificates travel in envelopes, what
  happens when absent — fail closed to today's roster path, or degrade?
- **Send-time vs read-time validity**: Option 3 verifies "was a member when
  the certificate covered it"; does any consumer need "is a member now", and
  does conflating them reopen the alias-reuse hole in the other direction?
- **Hosted custody**: for `verified_custodial` senders the operator signs;
  does certificate-chain verification change what that verdict may claim?
