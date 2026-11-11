# Human assurance and protected signing

Status: **contract draft for aweb-acxy.1; not an implementation or release
claim**. Juan approved the architecture on 2026-11-11 at 19:06 UTC. This
document specifies its shared policy boundary for hosted and independent
deployments. The typed catalog and behavioral cases live in
[`vectors/human-assurance-v1.json`](vectors/human-assurance-v1.json).
Consumer interfaces and contributor sections must be reviewed together before
this draft is frozen. Existing installations do not become conforming merely
by installing this document.

## 1. Independent facts and authorities

Login proves account access. A verified `kind=human` ID certificate records
that its issuer vouches for one person. A passkey assertion with user
verification (UV) proves use of that enrolled credential with its UV factor.
None alone proves that a person understood an act. The current B3 verifier
does not distinguish software from hardware authenticators or establish
hardware attestation. Stronger requirements need explicit policy and tests.

Ancestry answers who is responsible; it grants neither membership nor resource
access. Membership is team-controller authority. An address is
namespace-controller authority. Custody says who can use a private key. A
verified nearest human, account association, team owner, role holder and
credential holder are distinct facts and must not substitute for one another.
For a human leaf, the responsible human is the leaf itself.

One OSS library, embedded in an existing trusted server process, controls
human, namespace-controller and team-controller signing in supported
deployments. Cloud imports the same published package with account/custody
adapters; an independent operator uses its own server and registry. No Cloud
account, Cloud credential or public-registry fallback is required. Worker
agents retain their own **agent** keys and may sign permitted agent operations.

The signer accepts named, typed operations, constructs the artifact itself,
and refuses unknown operations, arbitrary-byte signing and key export. The
fixed minimum below is code, not a configurable exemption. Deployments may
add approvals, tighten scope or shorten time limits. Relaxing such additional
policy requires its current authorized human's live approval; it cannot relax
the minimum. A self-hosting administrator modifying the software is outside
this enforcement claim.

### What a remote verifier can establish

The v1 ID certificate and team certificate formats do not acquire an assurance
field. Their signatures establish issuer authority under their existing
verification rules, not whether the issuer used this signer or a passkey.
Remote consumers trust the issuer's signing policy. A previously token-issued
root cannot be relabelled as gesture-confirmed: its transition requires an
explicit, reviewed revoke/re-endorsement plan. Existing cryptographic
verification, current-head rules, expiry and revocation remain mandatory.

The browser and confirmation display are trusted. A separate trusted device
is deferred. An agent controlling the display can misrepresent the act; a
hardware touch alone does not repair that. Inbox or browser access available
to that same attacker is not an independent recovery factor.

## 2. Typed operation catalog

Each catalog row contains `operation`, `variant`, `key_role`, `enforced_by`,
`origin`, `authorizers`, `payload_binding`, `rule`, `bounds`, `policy_version`
and `audit`. The pair `(operation, variant)` is unique. Variants are disjoint
server-selected classifications, never a caller-selected bypass. The policy
reference is `aweb.human-assurance/1`; each deployment also retains an integer
policy version. Artifact versions such as `aweb.owner-act/1` remain separate.

`enforced_by` distinguishes the protected `signer`, an `app_b3` live-approval
consumer and an `app_verifier` checking already granted authority. A
passkey-only application effect need not manufacture a controller signature.
`key_role=none` means no protected key is needed, not no authorization.

`live_floor` requires a current eligible human, fresh UV bound to the exact
operation, and one consumption. `bounded_unattended` requires the named
existing authority and all listed bounds; it is not anonymous permission.
First enrollment is the explicitly specified bootstrap exception to requiring
an already enrolled passkey; recovery is its own delayed operation. Neither is
an ordinary unattended governance variant.

The exact request binds service/origin, operation and variant, selected key
authority and current key version, subject/key, target, domain/team/holding,
rights, every artifact field, expected current state/head, deployment policy
reference/version and the operation's idempotency identifier. A display is
derived from that frozen request, never a second request rebuilt from labels.
Omitted, unknown or duplicate fields, ambiguous targets and unknown authority
evidence refuse. The catalog references existing artifact encodings; it does
not replace their domain separation with a generic JSON-signing interface.

### Minimum requiring a live exact act

* Human ID issuance, by either a namespace or a verified human; deployment
  root endorsement; root replacement without old-key continuity; changing
  the responsible human or a human-issued parent edge.
* Human, namespace-controller and team-controller key rotation/recovery;
  credential binding/change, recovery-contact change and changes to the set
  of humans authorized for a protected key.
* Human ID revocation and revocation of a human-issued deployment-root
  endorsement, within the existing subject/parent/namespace revocation rules.
* Human membership admission/removal, team/controller ownership changes,
  controller permissions and unattended admission policy changes, event-hook
  activation/change/revocation.
* Human-role designation/removal and credential recovery; log retention,
  explicit erase and legal hold changes; creating or widening resource access;
  policy-required approval of individual resource use.

Human issuance and human team admission are **two independent approvals**.
One tap must not sign both, nor sign a queue of otherwise separate acts.
Recipient acceptance alone never supplies the team's owner authority.

### Permitted unattended neighbors

Agents issue agent children under the existing ID rules; this is identity
creation only. The authorized deployment root may request agent-only team
admission through a bounded controller interface. No raw controller key or
resource grant accompanies that ability. A policy can require approval for
each admission as an additional restriction.

A registered agent, including the root, may rotate using its old key's
continuity proof for the same identity and unchanged rights, with corresponding
membership renewal. Re-signing unchanged child ancestry also remains routine
and requires retained issuance provenance. A local `did:key` cannot rotate in
place. Without the old key, a parent can issue a **new child identity**, never
take over the old stable ID. Replacing the deployment root needs its human.

Agent-to-agent subtree moves may be unattended only when rights are unchanged
and the before/after **verified nearest_human** is identical. An unavailable,
unknown or invalid result cannot qualify. A changed human-issued parent edge
requires live approval even if a loose human label appears unchanged. Existing
child possession, current-head, issuance and registration checks still apply.

An agent may revoke its own agent children within existing revocation rules.
Unregistered local leaves have no portable per-ID revocation; membership
removal is separate. The existing 60-second ID-status bound remains; do not
promise instantaneous worldwide revocation.

Team-controller rotation remains distinct from certificate revocation. It does
not silently revoke existing member certificates. An operator handling a
compromise must explicitly inventory/revoke affected certificates and renew
the intended memberships; rotation alone is not containment of certificates
issued by the old key. Every verifier still applies its existing key/history
and revocation rules; new owner acts require the current controller. This
preserves [the registry's explicit certificate lifecycle](awid-sot.md#certificates)
rather than changing membership as a side effect of key maintenance.

The AWID bootstrap rule being implemented in acxc.69 permits skip-DNS for first
registration only. Replacing an existing controller still needs its current
controller authority or the supported recovery route. The signer cannot turn
a bootstrap flag into controller replacement authority.

Already granted work, authorized reads/export, drafts, authorized access
narrowing and preauthorized containment remain available. Containment may stop
work, disable access or credentials and cancel approvals. It may not install
credentials, replace a human, transfer ownership, erase/redirect audit or remove
a human-role holding through a side door. Last-owner protection still applies.
These restrictions also apply to SCIM-triggered containment. Re-enabling access
requires live approval. Containment must not wait for a ceremony or remote Logs.

## 3. Origin, holding and bootstrap

The server exposes the shared ceremony at a configured, pinned HTTPS human
origin. A separate configured request origin accepts request authentication.
These may be mounts of the existing server composition; they are not a new
approval-service product. Origin/registry selection comes from trusted
deployment configuration, never a URL supplied in an approval response.
For non-app governance, an explicit operator-provisioned protected-service
profile binds `service_id`, request origin, human origin/RP and authoritative
registry/key-authority references. No new AWID DNS or team-server discovery
field is introduced here. Existing app scopes retain pinned manifest origins.
The profile is public configuration, not authority. Team-auth headers never
go to the human origin. Browser session protection,
CSRF and WebAuthn origin/RP checks are necessary but do not replace the UV
approval for a floor act.

A holding has a typed authority scope independent of an application owner
installation:

* Application scope: exact service/installation and role, with the human
  principal and identity domain bound to the in-effect holder.
* Protected-key scope: exact signer service, key-authority kind and stable
  authority identifier, with its currently authorized human ID and domain.

Account ID, email, team name or nearest-human inference cannot choose a
holding. One account may hold multiple humans in different domains. Every
ceremony call resolves the explicit scope to its current subject; the effect
adapter locks/rechecks the account/session/human association and authority
through commit. The set of humans allowed to authorize a key is separate from
each human's set of credentials. Credential add never appoints another human.

The shared context extension is versioned and discriminated. Existing
`PasskeyInstallationContext(app_id, team_id, installation_id, generation)` and
its retained-proof encodings remain readable unchanged. A new protected-key
context contains `v=1`, `kind=protected_key`, `service_id` (the configured
signer identifier), `authority={kind,id,domain}`, `human={id,domain}` and
`generation` (the authoritative association generation). Authority kind is
exactly `human_identity`, `namespace_controller` or `team_controller`; its ID
is respectively the human stable ID, namespace domain or canonical team ID.
No private key locator appears in the public context. Application scopes keep
their installation/role/principal binding; a protected context is not coerced
into that type. The context discriminator and all context fields enter the
shared retained-proof commitment. Changing a generation invalidates unused
approval rather than silently rebinding it. Package .2 implements this one
extension; it must preserve existing app proof vectors.

The protected-service scope is admitted before any application role. It binds
an explicit human to existing operator-controlled authority; it is not a
Secrets installation or a team membership fabricated to satisfy B3. Initial
bootstrap can register its pending human under namespace authority after that
human's exact enrollment ceremony, then request the separately approved team
membership. A prior registered human is reused after current evidence checks;
bootstrap must not mint another human because lookup or key access failed.

### First enrollment precedes application roles

The deployment pins the signer origins, registry and initial key authorities
through its existing operator-controlled provisioning boundary, outside worker
access. The initial human association is an explicit bootstrap record under
that boundary, not a worker token or an inferred team member. The enrollment
baseline in the hosted profile is an email-verified browser session and the
existing B3 enrollment and recovery checks. In the independent profile it is
one recorded administrator action on the protected signer host, not a
worker-accessible network endpoint. The action binds the first explicit human,
key authority and credential at the pinned origin, and is consumed once.
Bootstrap establishes only the first authorizer set; later set changes are
live floor acts. These proofs establish account/operator authority, not
personhood.
Generate/retain any initial human key only in protected custody. A provisional
bootstrap record permits only that exact enrollment and associated initial
identity registration; it is not a standing general signer unlock.

Complete the first credential's UV registration bound to the selected human,
authority and origin. An operator-supplied or worker-readable bearer token alone
cannot perform this binding. Repeated enrollment resumes the same subject and
key; conflicting or ambiguous existing state refuses. Subsequent human
issuance and team admission consume separate live approvals. Team membership
can therefore be established before installing Secrets or Logs.

The first Secrets owner and Logs reader are then designated by a team-controller
`human-role.designate` act after the current team owner's live approval. The
app verifies the act, the selected human's own kind and current membership.
The signer does not depend on being a Secrets owner to establish that first
owner. Recovery without a working credential uses the separately authenticated
recovery authority and the 72-hour floor; it cannot re-enter initial bootstrap.

## 4. Ordinary human authentication without worker custody

The protected server constructs request authentication for a closed set of
ordinary operations: current membership/certificate reads, connect using an
already issued certificate, authorized status/mail reads, permitted message
send, and a handoff start for the same human and explicit scope. It binds the
exact configured destination, method, path/query and body to the selected
principal and team. The consumer still checks its own membership and resource
policy. Private registry member-key reads use the actual member authority and
that team's configured registry, never a public or controller fallback.

Interactive console read/connect/handoff signing as the human requires a B3
UV LOGIN session bound to the exact human, holding and credential, at most
900 seconds. Credential retirement ends that session. A cookie, API key or
CLI preparer token is not human-signing authority. This console-session rule
is distinct from the independently authorized linked-channel MAIL path below.
A short authenticated session can browse, draft and stage; it cannot approve
or activate a protected change. The supported path keeps the human key in the
server and uses the one shared handoff with an in-memory ephemeral session key.
It issues no reusable governance approval and installs no background human
signer on the worker. The adapter must classify operations by a closed route
and typed payload table, not by `GET`, an arbitrary installed-tool label or
whether team-auth happens to work. Generic `id request --team-auth` with human
authority is not an arbitrary path/body signing escape.

A restricted requester can initiate the protected-service login without an
existing human team-auth signature. After the selected human's UV LOGIN, the
server may construct the typed H-signed app handoff start. The app's existing
same-signer/scope check still sees H, not the initiating agent. The client uses
the shared page/module and pinned service profile, not a local human keychain
or passphrase fallback. Applicable app RP/login checks remain distinct; no
account cookie is promoted to B3 LOGIN by this bootstrap of the session.

Channel MAIL remains a separate narrow operation: verified retained speaker,
current linked-channel/delivery authorization, recipient and exact retained
mail/chat payload only. It does not require a B3 UV login or periodic
15-minute reauthentication. The authorized channel binding is sufficient for
this named messaging operation, never for a console session or governance.
A CLI token, API key or account cookie is not that channel authority, even
when it asks for a well-typed MAIL/chat payload; it cannot make the signer speak
as the human.
Missing/revoked channel authority refuses under existing ingress rules;
transient infrastructure failure remains distinct. Recovery of an already
committed signature returns the frozen result and nonce without re-signing.
Publication still checks its current delivery authority; an unpublishable
artifact cannot silently turn into a newly signed operation.
Channel login, a mail signature, an
installed-app token or a session signed for reading cannot be presented to
human issuance, owner acts or any governance signer operation.

## 5. One handoff and one operation receipt

The shared page/module gains a governance-approval mode for the typed
protected-key scope. Existing app `session`/`credential` handoffs and
`session_actions` remain their own compatible lane. The governance mode must
not invent an app installation merely to host identity governance. Package .5
owns this single client/browser flow; package .2 owns the shared signer/receipt implementation; .4 and .6 mount adapters.
Pinned request/human origins, no redirects, loopback/fallback binding,
in-memory ephemeral keys and X-Console request protections remain as specified
in [human confirmation](design/human-confirmation-from-aw.md). Scope adaptation
is additive for existing app consumers.

Before opening the browser, prepare gives the client the operation identifier,
digest and frozen typed payload. The client retains the non-secret identifier
and digest for recovery; this creates no authority. The server retains the same
binding under the authenticated requester and authority scope. A different payload, key, target, human or policy
under that identifier refuses; retries must not issue a different act. An
authorized read of that identifier returns the retained outcome. An approval
alone is not a committed effect.

CLI preparation and lookup authenticate the same requester under an explicit
restricted credential: an agent/root request proof or scoped discovery login
can prepare a human act, never approve it. They do not require the worker to
hold a controller key. The human browser separately checks its current
approver session and the explicit holding. A cookie or operation ID alone
cannot execute the act. The shared page displays the same frozen payload,
digest and fingerprint that the CLI displays.

The receipt states are `pending`, `refused`, `committed` or `unknown`, with
explicit reasons such as expired approval, spent-but-uncommitted proof or an
unreconciled external effect. A missing record is distinct from a refusal and
from proof that no effect occurred. Pending carries its expiry; refused carries
a stable reason. A running effect is pending. Unknown causes the CLI to report the identifier and exit nonzero,
never automatically prepare a new act. A redirect only wakes the client; only
a receipt establishes committed. Bounded polling is part of this product
client flow. Access is checked before
revealing a receipt. A response lost after commit recovers the exact result
without another signature. A state reader must serialize with an in-flight effect before
reporting spent-but-uncommitted. Concurrent requests produce one outcome.

The shared library ports are `prepare(CatalogOperation) -> PreparedOperation`,
`approval_options(operation_id)`, `execute(operation_id, proof)` and
`receipt(operation_id)`. The prepared record freezes the client-known ID,
request digest, typed holding, key identity/generation, policy reference/version
and protocol payload. Tokens/cookies can authenticate preparation or authorized
lookup within their scope; they never fulfill the live floor. An internal
typed custody adapter resolves an existing protected key reference; missing
references refuse, never generate or rotate a replacement. A current-authorizer
adapter supplies original-transaction prepare/check and synchronous deadline
checks. `AuditSink.emit(event, transaction)` remains the local audit port.

Several explicit domain-authority bindings may refer to the same existing
protected key reference. Each binding must match current authoritative
evidence; sharing a reference grants no authority in another domain. Reference
preparation/import, reader cutover and erasure are separate operator actions.
The adapter must not duplicate ciphertext or silently rotate a controller to
manufacture a one-domain/one-key relationship.

For credential changes, the SQL-only `receipt(tx, change)` hook records the
exact permitted result in the original effect transaction. The consumer must
associate the client-known operation ID with the exact challenge, scope,
subject and verified credential binding before execution. Protected signer
consumers always supply the hook; compatibility optionality for old B3 callers
does not authorize an unreceipted new signing path. Receipt access expires only
under an explicit retention/access policy; retiring a credential must not
erase its committed operation result. Lookup grants no renewed action rights.

Credential mutation uses ordered write preparation: authority/typed retirement
gate and role holds, then one B3 write preparation, then the consumer's
remaining authority holds. Its mutation fence returns the original-transaction
`PreparedCredentialChange`, which B3 validates and reuses. A shared-lock
usability check followed by a write-lock upgrade is not equivalent. Existing
enrollment/contact fence contracts remain compatible. Retained proof is
historical evidence; it never substitutes for current credential/holding checks.

Approval consumption, local effect and durable local audit/receipt share one
transaction and the existing B2/B3 fences. If a signed artifact is delivered
to a separate registry/app, signing and remote application are separate states:
retain the exact signed artifact before release, reuse its existing nonce/head
and reconcile the remote outcome. Never claim cross-service atomic commit or
blindly re-sign after a timeout. No network call belongs inside the final
effect fence. Exact API types/routes are assembled with package .2; these
requirements are not permission for each adapter to create its own store.

The signer enforces a UV age of at most **300 seconds at the signing effect**,
bound to one request. Conservatively use the original approval challenge's
issuance time plus 300 seconds, capped by its original expiry and every other
applicable deadline. Do not start at a `verified_at` stamp written after an
awaited counter update. The owner-act verifier independently enforces a lifetime
of at most **600 seconds**, with its existing current-key and prepared-evidence
bounds. A console session of at most **900 seconds** never extends either.
Other existing ID/B2/B3 freshness bounds remain separate. Waiting on a lock
does not restart a deadline. Recheck effect-local deadlines after the final
await, before commit, rolling back a stale effect.

Signing audit starts with the signer, before any Logs installation exists.
Governance requires its durable local record in the effect transaction; an
optional downstream recorder is not the source of authority or an enrollment
prerequisite. Containment remains available during remote logging failure and
records its local outcome. Audit must distinguish bootstrap, live approval,
bounded unattended work and containment; exclude secrets and private keys.

## 6. Working credential changes versus recovery

`human-credential.add` and `human-credential.replace/current_passkey` require a
CURRENT usable credential of the same holding with fresh exact-act UV. Verify
the new credential's UV registration first, retain its exact credential digest,
and bind the current credential's approval to that digest, RP/origin, holding,
human, operation and selected retire target. The new credential cannot approve
itself. Browser `allowCredentials` is not a server-side membership check.

Add retains existing credentials. Replace inserts the new credential and
retires only the selected old credential atomically, never leaving zero usable
credentials. Retired credentials lose their sessions; replacement invalidates
the holder's unused approvals, including approvals made with its other
credentials. It does not undo committed acts or remove the holding. A live
operation racing recovery, subject replacement or retire-target revocation
refuses stale binding and rolls back.

Default maximum active credentials is **5 per holding**. An owner-approved
`human-credential.cap-set` changes the finite bound; stricter bounds may be
lower, never zero. A full set refuses additions without eviction. Replacing
one credential may succeed at the cap because the count is unchanged. Lowering
a cap does not evict credentials from an already larger set.

`human-credential.replace/controller_recovery` remains distinct: no usable
credential means separately authenticated recovery, with the **72-hour**
floor and frozen approvals. Security-contact change retains the **24-hour**
delay. A credential act cannot change the contact, and neither waits for nor
cancels a pending contact change. Notify the contact effective immediately
before the act. Notice failure does not reverse a committed result. Notice
delivery and no-contact holding behavior must match the shared B3 decision;
this contract does not create an independent retry subsystem.

The approved B3 notice behavior is best-effort delivery after commit, with a
structured delivery outcome and contact hash in the committed audit. A crash
between commit and send can lose the notice; no durable notice outbox/retry
has been approved here. A holding with no notice contact needs the shared
policy ruling before its working-credential change can be declared supported.

A usable stolen passkey plus its UV factor can add a credential. Notices
provide detection, not prevention of that case. The receipt exposes committed
credential changes independently of notification success.

## 7. Custody migration and compatibility

Worker OS users, containers, processes, mounts, backups and keychain access must
not reach protected human/namespace/team-controller private keys or unlock
material. Merely hiding a filename, asking for a passphrase, or checking an
agent-runtime environment marker does not establish isolation. Existing keys
enter protected custody through a separately approved operator-side import,
not through worker request bodies or a key-export endpoint. Preserve the exact
public key, ID, registry/origin bindings and issuance history. No automatic
rotation, remint, global-registry move or production write follows from build
authorization.

Inventory the existing human keychain entries and encrypted backups,
namespace controller stores, team-key stores, hosted DB custody, custody
sockets and worker-visible grants. A key for another team is not safe merely
because a worker selects a different active team. The isolation finding is
about accessibility and authority, not a directory basename. Package .8 owns
per-installation migration approval, backup/removal and rollback limits.

Legacy artifacts remain verifiable under their original formats. The new
signer removes unsupported human/controller signing entry points rather than
calling them as a fallback. Existing client requests must either use the
compatible restricted operation or return an explicit upgrade/approval-required
refusal. Inventory every affected consumer before activation; do not silently
weaken the signer to preserve a bearer-only governance route.

Agent identity creation remains in the released parent/child exchange. A local
agent can parent a local child; registered children require an eligible
registered issuer under the existing ID contract. A deployment root can issue
a registered descendant when it is that actual issuer; the chain must show the
real parent, never an invented local intermediary. Membership admission is a
separate controller effect and does not mint or endorse an identity itself.

## 8. Existing entry points and task mapping

The following inventory is source evidence, not evidence that adapters have
already closed these paths. Cloud contributes its hosted route-level trace;
application contributors supply the app rows. A supported composition must
route every key use through its classified operation or refuse it.

| Existing family | Source | Required disposition |
| --- | --- | --- |
| Human creation, keychain signing and backup | `cli/go/cmd/aw/id_human.go`, `cli/go/awid/human_signer.go`, `cli/go/awconfig/human_keychain.go` | Protected enrollment/issuance and operator migration; no worker passphrase fallback. |
| Human/root/agent child exchange and registration | `cli/go/cmd/aw/id_child.go`, `id_parent.go`, `id_create_parent.go` | Human/namespace uses are typed live operations; eligible agent issue/re-sign remains unattended. |
| ID rotation, recovery and revoke | `cli/go/cmd/aw/id_rotate_key.go`, `id_rotate_key_recover.go`, `id_revoke.go` | Classify key type, continuity and target; no human/root replacement under the agent exception. |
| Namespace address, controller, team creation and deletion | `cli/go/cmd/aw/id_namespace_*.go`, `id_team.go`, `id_team_rotate_key.go`, `id_team_server.go` | Enumerate exact controller effects; authority expansion/ownership changes require live policy, unknown operations refuse. |
| Team invite/admission, certificate renewal, member replacement/removal | `cli/go/cmd/aw/id_team.go`, `team_spawn_authority.go`, `team_replace_key.go`, `team_human.go` | Root agent-only bounded admission; human admission separate live act; unchanged agent continuity renewal only. |
| Human reads/connect/team-auth/mail | `cli/go/cmd/aw/human_participation.go`, `id_request.go`, `id_registry_read.go` | Section 4 typed restricted server authentication; no arbitrary installed tool/path signer. |
| Resident custody app/message signing | `cli/go/cmd/aw/custody.go`, `custody_app.go` | Agent resident work remains scoped; never load a protected human/controller key into worker custody. |
| Controller owner/hook acts | `cli/go/cmd/aw/hooks.go`; [owner act](owner-act.md) | Shared signer live approval and existing downstream verification/nonce consumption. |

Hosted adapter inventories must cover every browser-session, CLI-token,
installed-tool and linked-channel signer, including cached-member projections,
certificate reconciliation, immediate-connect recovery and namespace/human
re-establishment. Classify each path before minting; a cache or recovery path
is not an exemption. The early hosted `aw id create --org --human-parent`
branch is not made safe by a later local terminal check: its token-only human
issuance authority must be removed. Exact hosted route traces remain with
that implementation's owner; no private application schema governs this OSS
contract.

Existing tasks remain tracked; the build does not discard their delivery scope:

| Prior work | New scope |
| --- | --- |
| acxt deployment-root journey | Attribution/continuity baseline only; not proof of protected controller custody. Preserve the accepted test and add .4/.7 isolation/admission controls. |
| acxv naming cleanup | Preserve its independent landing; no replacement design name restores removed authority. |
| acxu browser file consent | Superseded implementation by .5 shared ceremony and .6 Cloud adapter; retain the frozen historical note, no new file-transport implementation. |
| acwd / C3 / 4.6 and existing human-role handoff | Preserve their shared app API; adapt the signer and typed scope additively in .2/.3/.5. |
| Secrets 16.41, 16.43a+b, 16.44.3 and full provider/runner acceptance | Continue in .9 with catalog compatibility; no restart or dropped scope. |
| Existing deployment roots and team/controller stores | .8 inventory and explicitly approved migration; .7 reports findings, never auto-remints. |

## 9. Acceptance boundary

The vectors pin the policy distinctions, including same/different/unknown
nearest human, old-key continuity versus new-child lost-key recovery, issuer
kind, first enrollment, approver sets versus credential sets and recovery.
They are policy scenarios, not new cryptographic test vectors or a duplicate
signer engine. Packages .2–.6 must exercise them against their actual shared
implementation; static catalog validation alone is not runtime acceptance.

The independent profile must use customer registry/service origins with no
Cloud credentials, exercise private member-key reads and wrong-registry
refusal, and prove ordinary request authentication and agent admission while
worker-held human/controller shortcuts fail. Hosted tests must trace all
issuance routes, including cached/recovery certificate paths and channel mail.
Each release names exact package/client/server/registry versions; no version
is claimed by this contract draft. Fresh setup and supported existing-state
upgrade are separate acceptance journeys.

## 10. Draft freeze questions and evidence

The following details still require paired contract/security review; they are
not permission for consumers to invent fallback behavior:

* The exact cap-change subject and trusted evidence port for non-team
  protected-key scopes, alongside the app team-controller owner-act variant.
* The working-credential change policy for a holding with no notice contact.
  The shared credential owner is obtaining that ruling; no contact-remint or
  delivery subsystem is implied here.
* The unchanged-ancestry re-sign variant for a protected human/namespace
  issuer: it implements the approved routine re-sign exception, requiring
  unchanged ancestry, subject possession and exact retained provenance. It
  must not become new endorsement or a human-edge change without approval.
* The complete controller operation inventory and exact restricted route union
  in each adapter, with the shared versioned context/receipt API and actual
  public HTTP mounts. Preparation ports above define the boundary; this draft
  does not claim an already released endpoint.

Source contracts are [ID certificates](id-certificates.md),
[AWID](awid-sot.md), [owner acts](owner-act.md),
[owner-act delivery](owner-act-delivery.md),
[human-role holders](design/human-role-holders.md) and
[human confirmation](design/human-confirmation-from-aw.md). The application
catalog/first-role/entry-point cases were contributed by the app-contract lane;
its separate Secrets bootstrap correction is included with original authorship.
The B2/B3 port and lock-order contribution was source-read at
`27fbd08192a1997874da58abff8d151c0e7779ce`, based on the holder stack rather
than older main B3. These sources establish reusable boundaries, not completed
protected-signer integration. The independent reviewer must not ACK their own
contributed portions; security review covers the assembled contract.
