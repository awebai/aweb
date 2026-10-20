# Optional team credential lifetimes

Expiry is a team policy, unset by default. Live revocation remains the primary
control. Juan approved this rule on 2026-10-20 (coordinator fc7e04ef); Athena
approved the design and admin surface in c11beaf8. There is no global lifetime,
mandatory re-consent cadence, or cutoff for certificates without expiry.

The controller signs membership. Identity custody does not confer controller
authority: [Fully Hosted and BYOT](../byot-onboarding-contract.md:17) distinguishes
them. BYOT controllers choose at issuance. Hosted administrators manage the
policy through the existing team owner/admin check, scoped to the target team;
the host then acts with its existing controller authority.

## Policy and hosted integration contract

AWID is the canonical policy source. The controller-authenticated endpoint is
`POST /v1/namespaces/{domain}/teams/{name}/credential-lifetimes`; its signed
operation is `set_credential_lifetimes`, binding the team and full policy, and
accepts only the covering v2 controller envelope. The policy is a team-key-signed
`aweb.team-credential-policy/1` record, rather than unsigned configuration. Its
exact-team GET is anonymously readable on public and private teams, following S6
and team-server records. Readers verify it against the CURRENT team key, so a
self-hosted verifier needs neither a service token nor a member's private key.
Policy reads use an origin/team-scoped cache for at most 60 seconds, with no
expired fallback. Fetch failure refuses as `authority_unavailable`. An older registry
without the endpoint has no configurable policy and retains existing defaults.
An absent record means no policy; malformed, wrong-key or unavailable records
never become an absent-policy fallback.

The policy has four nullable maximum durations in seconds:

```
member_certificate
ephemeral_certificate
identity_grant
hosted_mcp_grant
```

All default to null. A positive duration opts that credential class into expiry.
The response includes the policy revision. Changes audit the controller actor,
team, old and new values and time in the registry transaction. No member or
session grant can set policy. The hosted service also audits the human admin.
The signed record contains `v:1`, `type:"aweb.team-credential-policy"`, team ID,
current team did:key, revision, UTC issued_at and the four nullable maxima.
Signing bytes are `aweb.team-credential-policy/1\n` plus canonical record JSON;
the body is `{record, signature}`, like the existing signed-record endpoints.
It joins the signed-records read and `resigned_records.team_credential_policy`
in team-key rotation: the complete-set checks require its new-key signature,
preserving policy/revision and changing only key/issued_at, in the same commit.
No record is stranded on the old key after an atomic re-signing rotation.

Cloud owns its dashboard API, with a target-team-scoped read and audited save
using `assert_team_role(..., min_role="admin")` today; it later moves the same
decision into `authorize()`. A service credential or team membership alone is
insufficient. Cloud signs the record and covering policy operation through the
public RegistryClient. Team settings → Credential lifetimes shows four rows, “No limit”
or a positive duration, no presets. Saving a certificate limit is blocked until
released verifier adoption has been measured. Cloud owns the adoption gate and
its UX-owner sign-off. It must not issue v2 early to members or peers.

Before saving a grant limit, show the count of affected existing grants and:
“Changing this limit takes effect within a minute. Grants issued
for longer than this limit, including never-expiring grants, will stop working.
Their owners must mint replacements.” No raw credentials belong in audit/metrics.

## Signed certificates and safe renewal

Certificate v2 adds `validity_class=member|ephemeral` and an optional, signed
`expires_at`. The controller chooses the class independently of `identity_scope`.
An absent expiry means unbounded. A present timestamp must follow issuance;
`now == expires_at` is expired, with no grace. Verifiers return 401 with
`certificate_expired`; malformed and lifetime-exceeded errors are distinct.
AWID registration refuses an over-policy duration with 422. Existing v1
certificates without expiry remain valid.

When a finite policy is enabled, certificates without expiry become due for
reissue. Lowering a maximum also makes over-limit certificates due. The final
third of a finite certificate's lifetime is its ordinary renewal window.
Disabling policy never changes an existing signed deadline; renewal issues a
new certificate without expiry. Revoked members are never renewed.

`aw id team renew-certs --team ... --namespace ...` is the controller's batch
operation. It preserves member identity, address and scope, changes certificate
ID, registers the replacement and only then retires the old certificate. A
failure must preserve the old active certificate: registry replacement must be
atomic, including its active-alias constraint. Members automatically fetch the
newest active own-key/team certificate, verify it against the current team key,
and install it. Fetching a public artifact does not authorize membership or
authenticate with an expired credential.

Cloud's scheduler performs that same controller-authorized replacement for
finite-policy hosted teams, with warnings when renewal becomes due. It also
handles removal of a prior lifetime by issuing unbounded replacements, then
stops scheduled lifetime renewal. It must recheck revocation and policy under
replacement concurrency; never retire the old artifact on a failed registration.
Revoking an issuing certificate still ends its old grants; renewal does not
silently transfer or broaden them.

## Atomic certificate rollover (review requested)

Existing AWID has one active alias per team and a plain registration INSERT
(`awid/src/awid_service/migrations/001_registry.sql:142`,
`awid/src/awid_service/routes/teams.py:870`). Separate register/revoke requests
cannot safely renew it. Renewal must use the new operation below.

`POST /v1/namespaces/{domain}/teams/{name}/certificates/{old_id}/rollover`
accepts `{"replacement": <CertificateRegisterRequest>}`. Controller authority
only, using the covering v2 controller envelope; no legacy form. Add operation
`rollover_certificate` and route-derived claims `domain`, `team_name`,
`certificate_id` (old ID), `replacement_certificate_id` (new ID) to the closed
acic.3 table. The envelope binds exact origin, method, path/query and full body.

Validate the replacement controller signature, policy, version and deadlines.
Require the old row's exact member key, alias, identity scope, stable identity
and address; renewal cannot replace a key or change membership. New and old IDs
must differ. Lock the current team/controller and old certificate in one
database transaction, then recheck authority, revocation and policy. Only an
active old row may roll over. Set its revoked timestamp, insert the replacement
and record the rollover link in that SAME transaction. The statement order is
necessary for the partial unique index; neither intermediate state is committed
or observable. Any validation/insert failure rolls back the old revocation.
One successful commit exposes the active replacement and revoked old tombstone
together. There is never a committed membership gap or revoke-first workaround.

New ordered AWID migration: nullable `replaced_by_certificate_id` on
`team_certificates`, with a composite foreign key to `(team_uuid,certificate_id)`.
Retain existing active-alias and certificate-ID uniqueness. A duplicate with the
same old/new IDs and identical registered replacement is idempotent only while
that replacement remains active; it never performs an INSERT/UPDATE. Different
replacement, revoked replacement, or independently revoked old ID refuses409.
No delayed request can reactivate an ID. Concurrent renewers serialize: one
different replacement wins; a losing request preserves committed state.

The public Python `RegistryClient.rollover_team_certificate(...)` and Go client
own the covering request. Cloud and batch renew-certs call these; no private
signing helpers. Both invalidation and tests cover certificate/revocation caches.
Rollover invalidates the caller's cached status for both IDs. Other verifiers
converge within the same at-most-60-second certificate-status TTL. A revoked row
with `replaced_by_certificate_id` reports 401 `certificate_replaced`, distinct
from disciplinary `certificate_revoked`. The response carries the replacement
ID. aw and channel-core/naapp-lib clients follow that exact same-team link,
verify the replacement under the current team key, require the same member
did:key, install it and retry the original request once. A failed fetch or
verification fails closed; never loop or fall back to root authority. Proactive
auto-fetch remains. The real-stack full-loop test rolls over, observes the old
credential refused, follows/installs and retries successfully; a second refusal
does not trigger another retry.
Real PG/HTTP tests: active-alias neighbor, failed registration rollback, successful
atomic replacement, duplicate/reordered retries, parallel differing renewals,
cross-team/non-controller refusal, body swapping, revoked tombstones and policy.
AWID0.5.31 is allocated by the coordinator; it must be
published and pinned before Cloud invokes rollover. aw1.36.46 is allocated for
the client integration. This section needs Athena review before route building.

## Grant minting and verification

Treat requested `ttl=never`, omission or null as unbounded input. The actual
deadline is the minimum of requested finite expiry, issuance plus the team's
identity-grant maximum, and issuing-certificate expiry, ignoring absent bounds.
If unbounded, API/CLI/grant.yaml retain `expires_at: "never"`. Otherwise mint
succeeds with the actual finite RFC3339 deadline. This contract ships in aw
1.36.46; that is the OATS integration floor, not a claim it is already published.
Expired/revoked authority cannot mint; a session grant cannot mint its successor.

At every verification, a current team cap rejects an existing never grant or a
stored issuance-to-expiry interval above the cap within the 60-second policy
cache bound. Do not shorten it
in storage or reset issuance. Signed/stored finite expiry and parent revocation
remain binding even when policy is removed. Expired grants return 401
`grant_expired`; an over-policy lifetime has its own refusal code.

Hosted MCP retains access tokens of at most one hour and sliding refresh
hygiene. Only a team MCP maximum adds an absolute consent deadline, anchored to
original consent issuance. Refresh never resets it. Changed maxima apply to
existing consent using that same anchor. Access and refresh tokens cannot outlive
the absolute bound. Without a maximum there is no periodic re-consent. Console
OAuth policy is unchanged.

## Delivery and evidence

Ship verifier support, codes and adoption metrics first (server, Cloud, clients,
including aw, channel-core/Pi, naapp-lib and OATS), then audited settings and grant
enforcement, MCP absolute bounds, batch renewal/member fetch and scheduler.
Enable v2 issuance only after measured adoption. Existing published v1 clients
remain supported throughout. New storage uses ordered migrations.

Real-stack boundary tests cover unset defaults and finite neighbors; signed
expiry at the boundary; tampering; admin and cross-team policy refusal; policy
changes; parent clamp; safe renewal failures; and revocation. The covering gate
runs once with `SUITE_LOCK_PRIORITY=release`; code review plus Athena precedes
integration. Cloud implementation belongs to its assigned seat; OATS belongs to
the OATS lead. The coordinator integrates cross-repository releases.
