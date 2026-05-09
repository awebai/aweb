# Fully Hosted and BYOT Onboarding Contract

This document is the product and engineering contract for customer onboarding.
The supported customer-facing choices are exactly:

1. **Fully Hosted**
2. **Bring Your Own Team (BYOT)**

There is no supported middle tier where a customer brings a custom domain while
aweb keeps that domain's namespace controller private key. Custom domains are
part of BYOT: the customer controls the DNS-rooted namespace controller and the
team controller.

## Fully Hosted

Fully Hosted means aweb operates the namespace and team authority for resources
under the hosted base domain, such as `*.aweb.ai`.

In Fully Hosted:

- aweb may create child namespaces under the hosted base domain.
- aweb may hold encrypted namespace controller keys for hosted namespaces.
- aweb may hold encrypted team controller keys for hosted teams.
- aweb may create address bindings for hosted namespaces.
- aweb may mint and revoke team certificates for hosted teams.
- identities may be self-custodial or custodial.

The hosted flow must remain the simple default path. It should not require the
customer to understand namespace controllers, team controllers, DNS TXT records,
or signed import payloads.

## BYOT

BYOT means the customer brings the DNS-backed namespace and the AWID team. BYOT
includes what earlier docs called BYOD and BYOIDT.

In BYOT:

- the customer controls the DNS zone for the namespace.
- the customer holds the namespace controller private key.
- the customer holds the team controller private key.
- the customer creates or authorizes AWID team certificates.
- aweb imports and projects customer-signed AWID facts into runtime state.
- aweb must not store or use the customer namespace controller private key.
- aweb must not store or use the customer team controller private key.

The dashboard may guide the customer through BYOT setup, but the authority stays
with the customer. Any dashboard action that imports a BYOT team must verify a
customer-signed statement from the team controller and fail closed on mismatch.
The CLI helper for this boundary is `aw id team import-request`: it signs the
`byoidt_import` payload with the local team controller key and prints the body
for AC import/sync without transmitting private controller material.

## Identity Custody Is Independent

Identity custody is a separate layer from namespace and team authority.

For Fully Hosted teams, aweb may offer:

- self-custodial identities, where the agent keeps `.aw/signing.key`.
- custodial identities, where aweb stores the encrypted identity signing key.

For BYOT teams, aweb may also offer custodial identities, but only for the
identity signing key. The customer still authorizes that identity into the BYOT
team with a customer-signed team certificate, and authorizes any address binding
with the customer namespace controller.

The correct BYOT custodial sequence is:

1. aweb creates a pending custodial identity: `did:key`, `did:aw`, encrypted
   identity signing key, and hosted runtime metadata.
2. The customer signs a team certificate for that `did:key` with the BYOT team
   controller.
3. The customer signs or maintains any desired address binding with the BYOT
   namespace controller.
4. aweb imports/syncs AWID facts and binds the pending custodial identity only
   if the imported `did:aw`, `did:key`, alias, and address intent match.

Before step 4, the pending custodial identity has no BYOT team authority.

## Removed Middle Ground

The removed middle ground was: "customer domain, aweb-held namespace/team
controller keys." That shape is no longer a customer-facing product because it
is hard to explain and creates two sources of truth for namespace ownership.

Retirement rules:

- New customer flows must not create cloud-held controller private keys for
  customer domains.
- Existing external managed namespace rows may remain visible for cleanup, but
  create/verify flows must direct customers to BYOT import.
- Code must not choose BYOT behavior by flipping `managed_namespaces.is_default`.

## Authority Boundary Audit

| Path | Authority Used | Fully Hosted Behavior | BYOT Behavior | Required Tests |
| --- | --- | --- | --- | --- |
| Hosted namespace creation | Hosted parent namespace controller | Allowed under hosted base domain | Not used | Hosted signup creates registered hosted namespace |
| Hosted team creation | Hosted namespace controller and hosted team controller | Allowed | Not used | Hosted team can mint hosted certificates |
| Address assignment | Namespace controller for address domain | Allowed for hosted namespaces | Must be customer-signed/imported fact | BYOT import never calls managed address assignment |
| Hosted Add existing identity | Hosted team controller | Allowed for hosted teams | Refuse; use BYOT import/sync | Hosted add rejects externally controlled team |
| Local `aw id team add-member` | Customer/local team controller | Only works if local key exists; hosted dashboard is the hosted path | Canonical BYOT membership path | Missing hosted key gives clear refusal |
| `/byoidt/import` | Customer team-controller signature | Not used for hosted managed namespaces | Imports/syncs customer-signed team facts | Dry-run, apply, conflicts, cross-org |
| BYOT custodial pending identity | aweb-held identity signing key only | Not used; hosted custodial path exists | Allowed only after imported BYOT team exists | pending, active, mismatch, reaped, revoked |
| Lifecycle delete/reassign addresses | Namespace controller | Only touch hosted namespaces aweb controls | Skip BYOT/customer namespaces | Deletion never signs for BYOT namespace |

## Why `is_default` Is Not a BYOT Switch

`managed_namespaces.is_default` is an ordering and protection flag for managed
namespace rows. It is not an authority model.

It currently affects:

- deletion protection.
- namespace ordering in dashboard lists.
- default namespace display.
- spawn invite namespace selection.
- dashboard JWT namespace lookup.
- lifecycle primary-address selection.
- persistent address assignment.

Changing `is_default` to make BYOT "win" would couple product authority to
unrelated UI and lifecycle semantics. BYOT selection must instead be explicit:
the local team is bound to an AWID team id and the BYOT import/sync path consumes
customer-signed AWID facts.

## Fail-Closed Rules

BYOT operations must fail closed when:

- the AWID team id is malformed.
- the AWID team is not found.
- the importing user lacks access to the target organization or team.
- the controller timestamp is stale.
- the controller signature does not verify against the AWID team controller.
- the target local team is already bound to another AWID team.
- the AWID team is already imported by another organization.
- a hosted-controller team is passed to BYOT import.
- a managed hosted namespace is passed as BYOT.
- a pending custodial identity's imported `did:key` differs from its stored key.
- a pending custodial identity's imported address differs from its requested
  address intent.
- a pending custodial identity has expired before import.
- AWID does not return the certificate blob needed for custodial activation.

## Regression Matrix

Minimum release-gating coverage for this contract:

- Fully Hosted signup creates hosted namespace, hosted team, and hosted
  custodial identity without BYOT concepts in the customer flow.
- Fully Hosted Add existing identity mints a hosted team certificate and returns
  usable setup commands.
- Hosted Add existing identity rejects externally controlled teams.
- BYOT import dry-run lists creates/updates/deletes/conflicts without writes.
- BYOT import apply creates a local team projection without storing customer
  namespace or team controller keys.
- BYOT import is idempotent.
- BYOT import rejects stale or invalid controller signatures.
- BYOT import rejects cross-org reuse of an already imported AWID team.
- BYOT import rejects managed hosted namespaces.
- CLI `aw id team import-request` signs the AC canonical payload with an
  interop-tested raw base64 Ed25519 signature and refuses hosted namespaces.
- BYOT self-custody projection remains custody `self`.
- BYOT custodial pending creation does not call hosted namespace, address, or
  team-certificate minting paths.
- BYOT custodial bind succeeds only when imported facts match the pending
  `did:aw`, `did:key`, alias, and address intent.
- BYOT custodial mismatch cases fail closed.
- BYOT custodial pending expiry reaps the pending identity and crypto-shreds key
  material.
- BYOT custodial certificate revocation retires the projection and crypto-shreds
  key material.
- Dashboard exposes only Fully Hosted or BYOT onboarding choices.
- Dashboard BYOT flow uses import/sync and customer-controller commands, not
  cloud-managed custom-domain verification.
