# Existing-installation key custody migration

Status: **proposed operator recipe for aweb-acxy.8; not an apply authorization**.
This moves existing installations toward the protected profile without replacing
identities, authorities, registries or application data. It enables existing
OATS and independently hosted deployments to opt into human IDs. It also gives
hosted operators the same custody boundary through their own adapters.

The governing authority is [human assurance, section 7](../human-assurance-contract.md#7-custody-migration-and-compatibility),
frozen at `584d76c9c9d7aae42b3d915bc1ab94cc1040a42d` and extended on main.
Source/tool observations below were checked at
`d52e8063e68610bff9d99e610fb75423dd164291`. A source seam is not a released,
qualified migration. The operator must pin the eventual compatible composition
and published artifacts before scheduling an apply.

The public recipe contains no deployment inventory, private locator or human
account identifier. The assigned operator retains a separate, access-controlled
annex with those facts, their dates, the exact action plan and approval receipts.
The OSS/hosted ownership boundary remains
[the onboarding contract](../byot-onboarding-contract.md#authority-is-separate-from-custody-and-hosting).

## Invariants and approval boundary

A custody move retains the same private key and public fingerprint, stable ID,
namespace/team authority, registry and service origins, memberships, bindings,
issuance history, passkey state and existing application data. Changing file
encoding from a PEM to the same seed in a protected store is not rotation.
A different public key, new human, new root, changed parent, different registry,
changed origin or wider admission policy is a separate operation; stop rather
than making that substitution to finish a migration.

Responsibility, account access, team membership, controller authority and custody
remain independent. A selected human H must be explicitly established for the
exact authority. The logged-in operator, deployment root, account owner or
old key-file owner is not automatically H. A current human ID is reused after
current identity/key/namespace evidence checks. A missing record, inaccessible
key or unavailable registry never authorizes creating a replacement human.
See [first enrollment](../human-assurance-contract.md#first-enrollment-precedes-application-roles)
and [protected service configuration](../protected-service-profile.md).

Build permission authorizes neither import nor activation. For production,
Juan decides **each exact action** through the established production operator:
reference preparation/import, provisioning H, reader cutover, protected-team
activation, removal of each copy class, environment removal and backup expiry.
A reviewed recipe or successful dry run supplies evidence for that decision;
it does not supply approval. Self-hosting owners authorize the corresponding
changes to their own deployment under their own recorded operator process.
This document authorizes no execution in either environment.

One already issued legacy token-route agent is an explicitly excluded item in
the private action plan. Do not revoke, reissue, reparent or relabel it, and do
not revoke its certificate by removing its old issuance route. Revoke and
re-endorsement require their separate human decision. No old artifact acquires
live-approval provenance merely because its key changes storage.

## Key-class disposition

| Existing class | Target custody and signer | Transition that preserves authority | Current executable boundary |
| --- | --- | --- | --- |
| Human signing key in hosted ciphertext or an operator keychain | Protected human-identity key, used only by the shared typed signer after the appropriate current H/credential/policy check | Import the existing seed through an approved operator-only adapter; compare its public key and exact stable ID/enrollment/issuer associations; bind the selected H separately; cut over every human-signing reader before removing old access | No generic human-key importer or keychain-to-protected-store conversion is established by the team-controller command below. An exact reviewed adapter and rehearsal are prerequisites |
| Human encryption keys, generations and bindings | Preserve the declared custodial or self-custodial encryption boundary, separately from signing | Preserve keys, generations, encrypted history and exact H/key associations; prove old ciphertext remains decryptable under the intended custody. A signing-key move does not authorize new encryption keys or message rewriting | Requires the encryption owner's explicit transition/retention evidence; neither controller import nor agent-retirement erasure is this operation |
| Namespace-controller keys | Protected namespace-controller reference; the shared signer performs classified namespace acts | Import each existing distinct key once and retain its current public fingerprint; attach explicit domain/authority bindings proven against the current registry. Preserve independent domain keys | The observed standalone host currently accepts team-controller custody only. Namespace import/bindings need their own reviewed implementation; do not call a creation or rotation helper |
| One parent controller duplicated across many domain/row references | One protected reference to that existing parent key, with separately checked domain bindings | Prepare all dependent references before deploying readers that refuse legacy storage; preserve other valid canonical keys. A shared key does not itself authorize another domain | Protected reference preparation, exhaustive reader cutover and copy removal are separate actions. A caller argument removal is insufficient if a resolver still falls back internally |
| Team-controller key in a local owner store | Protected team-controller custody; shared typed signer, never the worker's ordinary member signer | The existing `install-controller --source-pem` imports the identical controller after profile equality checks; startup checks the registry too. Retain the original certificates and membership history | This concrete importer exists. Its observed host is a revoke-only slice, not evidence that human issuance, root endorsement, admission or rotation are ready |
| Hosted team-controller ciphertext | The same protected team authority, through the hosted adapter | Approved unwrap/import/rebind with public-key equality and all team/account associations preserved; switch all controller readers before copy removal | A local PEM importer is not proof of a hosted ciphertext converter. Purpose/row-bound encryption cannot be relocated blindly |
| Controller ciphertext attached to deleted/retired records | Protected or quarantined custody according to independently established **current authority**, not a deletion flag | Retain the key if registry authority is live, private, unavailable or unresolved. Reconcile dependencies and revocation needs; authorize any destruction separately | A registry 404 is an inventory fact, not deletion approval. A 403 is not absence. Never destroy the last usable revocation-capable controller based only on local retirement |
| Legacy OATS minting-root home and referenced controller stores | Move human/namespace/team-controller material to protected custody; retain the root's actual agent key in its intended worker/resident boundary | Inventory the home plus every referenced controller store, socket, grant and backup. Reuse an eligible existing registered root; configure the exact protected service and separately approve root endorsement/admission policy | Do not treat `aw init`, a fresh root or a worker-home copy as a migration. The OATS/provider cutover must consume the reviewed signer/CLI interface |
| Ordinary endorsed-root/worker AGENT keys, app signing keys and data-encryption master keys | Their existing specified operational custody | Preserve these unless a separately classified change is authorized. Root agent custody is intentionally worker-accessible within its bounded policy | These are not automatically imported as human/controller keys. Their mounts, grants and backup access still matter to isolation |

The target is one shared typed signer embedded through the supported host or
hosted adapter, not a new per-app signing protocol. A public protected context
names service, authority, selected human and generation; it contains no private
key locator. Several verified domain bindings may resolve the same protected
key reference without duplicating the secret. See
[the embedding boundary](../human-assurance-contract.md#5-one-handoff-and-one-operation-receipt).

## Read-only inventory and the per-installation plan

Use the existing operator's read-only evidence first. Its timestamp, scope and
limitations are part of the evidence. Before an apply, obtain a current bounded
refresh through that operator, not through a worker's credentials or a fresh
copy of private keys. A replica snapshot, environment **names**, file ownership
and registry public records are distinct observations. Do not infer that an
unobserved keychain, mount, backup, credential store or process is clean.

Record these non-secret fields for each authority and copy class:

- Deployment/service identifier, canonical team/domain, selected registry,
  public controller DID/key fingerprint and human stable ID if applicable.
- Current key/version/history evidence and any ambiguity, pending rotation,
  duplicate reference, retired row or current private authority.
- Source custody category and operator-only source locator; target protected
  reference, explicit authority bindings, profile/scope generation and signer
  principal. Public review artifacts use symbolic locators instead.
- Every reader/writer and deployed version: web, workers, jobs, CLI, OATS root,
  independent client, issuer, registration/reconciliation and invite consumers.
  Search resolver fallbacks as well as direct callers.
- Existing passkeys and enrollment/recovery history, H association, memberships,
  installations, grants, approval authority, roles, outstanding operations,
  retained receipts and encryption-key/history dependencies.
- All reachable copies: OS keychain, configured and legacy homes, container
  mounts, environment, runtime memory/debug access, sockets, archives, snapshots,
  WAL and encryption/unlock keys. Count rows and distinct public keys separately;
  never equate a ciphertext-row count with a distinct-key count.

For OATS, include `.aweb-roots/<label>/.aw`, configured
`settings.oats.aweb.root`/`roots`, legacy external homes and their referenced
team-key stores. An unrelated active-team selection does not make an accessible
controller key safe. Include clients that never opted into human IDs but admit
members to a team selected for protection.

The plan is an operator artifact, **not a new network protocol**. It names:
source and target public state; exact tool/source and published package/image
pins; the closed affected-key/consumer set; action ordering; expected read-back;
per-action approval ID; backup classification; stop/rollback boundary; and
hashes of scripts/configuration containing no private key bytes. An action with
unknown source authority, unsupported importer or unqualified consumer is
`blocked`, not `ready`. Inventory counts are dated expectations to reconcile,
not numbers a script must force the database to match.

## Supported commands and what they actually do

The following are command **templates for the authorized operator**. They are
not commands for an agent to execute now. Use the package environment matching
the eventual approved source/published composition. Paths are illustrative,
operator-selected locations, never guessed sources.

Pure public-profile validation, with no key import or service/DB connection:

```sh
PYTHONPATH=server/src python -m aweb.protected_signing.profile /config/protected-profile.json
```

This validates public structure/origin/key-reference consistency only. It does
not verify current registry authority, provision H, inspect secret custody or
prove that a deployed service can sign.

For a **team controller**, after separately approved private destination and
source provisioning, as the protected service OS user with the host's selected
profile/scope/settings:

```sh
python -m aweb.protected_signing.operator install-controller \
  --source-pem /private-provisioning/team-controller.pem
```

Source:
[`operator.py:32`](../../server/src/aweb/protected_signing/operator.py),
[`custody.py:23`](../../server/src/aweb/protected_signing/custody.py), and
[HOST.md, controller installation](../../server/src/aweb/protected_signing/HOST.md#controller-key-installation-backup-and-cutover).
It reads an existing PEM, compares the selected profile's public key, and
exclusively creates a mode-0400 file under a real mode-0700 directory belonging
to that OS user. It never overwrites, generates, registers or rotates a key.
The serving composition also checks the registry's current key. A destination
that already exists is a stop/reconciliation condition; do not remove it to
make a retry succeed.

This is an **apply**, not a dry run. Public-key equality does not prove full
custody isolation. The file checks do not certify ancestors, mounts, sockets,
debug access, OS-keychain reachability or backup isolation. Conversion does not
remove the source PEM. Provisioning and cleanup are distinct approved actions.

Other existing host commands are also **not read-only dry runs**:

```sh
python -m aweb.protected_signing.operator bootstrap --requester DID_AW --contact CONTACT
python -m aweb.protected_signing.operator check
```

`bootstrap` writes the exact initial authorizer/requester state and sends the
existing enrollment link; the selected human then completes the actual UV
ceremony. It is not approval of later acts. `check` opens the real composition
and invokes migrations before validating provisioning
([`operator.py:79`](../../server/src/aweb/protected_signing/operator.py)). It
must not be placed in the recipe's no-write inventory phase merely because
its name is "check". Existing completed/revoked credential history cannot be
reset into first enrollment. The command's currently supported authority slice
must match the plan; it cannot bootstrap a missing human-key importer.

There is no documented generic `migrate-keys --apply`, namespace importer,
Cloud ciphertext importer or OATS-root importer in this checked baseline. Do not
invent one. For those classes the recipe's exact next action is to obtain the
responsible package owner's pinned operator-side tool, security review and
rehearsal before import. A test fixture or creation helper is not that tool.

## Ordered operator actions and required evidence

Run each phase for the smallest explicitly approved authority/cohort. Stop on
mismatch; do not broaden the cohort or generate replacement material.

1. **Inventory and decide.** Freeze the per-installation plan and affected
   consumers. Establish H's exact existing identity/custody or record the
   separate decision to create/enroll H where no eligible identity exists.
   Distinguish unknown from absent. Do not run initialization as discovery.
2. **Prepare protection and recovery.** Pin service/request/human origins, RP,
   authoritative registry, public keys, policy versions and bindings. Use a
   separate OS/security principal and protect memory, filesystem, keychain,
   sockets, service management/debugging, mounts, unlock material and backups
   from workers. Co-residence under the worker UID is not isolation. Identify
   the compatible old/new schemas/readers and a tested recovery destination.
3. **Rehearse without production authority.** Exercise the exact tool/config
   shape on isolated synthetic authority and on an authorized stateful copy
   when its privacy/custody policy permits. Cover nonempty installs, existing
   grants/roles/passkeys/receipts, unchanged-key import, mismatched keys,
   interrupted/duplicate import and missing references. Use test-only public
   identities for demonstrations, not production signing seeds. A lab result
   must state which real existing-state transition it covers.
4. **Prepare/import references under approval.** Quiesce the selected authority's
   old key writers while keeping unaffected authorized work available. Take
   the approved consistent backup. Import the same key through its reviewed
   operator adapter, compare public fingerprints and read back exact authority,
   H, policy and history bindings. For a shared parent, prepare all dependent
   bindings before a fail-closed reader cutover; preserve distinct canonical
   keys. No raw key enters a worker or an HTTP request body.
5. **Establish authorizers through the supported path.** Reuse existing current
   H/enrollment/credential state; do not copy passkey/session rows as enrollment
   proof. Where an explicitly approved first enrollment is needed, use the
   recorded operator/bootstrap and real UV registration at the pinned human
   origin. Changing an existing authorizer or recovering a lost credential
   follows its live/delayed operation, never deleting bootstrap history.
6. **Cut over consumers before enforcement.** Qualify every legacy reader and
   writer on the protected reference/interface. Upgrade all affected OATS,
   independent and hosted consumers; announce the exact team migration even
   to non-opted-in invite users. Confirm compatible released artifacts and
   restart long-lived processes. Protected teams' agent admission **and
   renewal** must use the configured root/policy path; a legacy invite gets
   the specified upgrade refusal, not a local-controller fallback.
7. **Activate and observe the exact protected cohort.** Under its separate
   approval, enable the protected policy only after the relevant operation
   catalog/consumer is supported. Preserve the registered root's ID/key and
   real ancestry. Endorsement is one exact live act disclosing the existing
   bounded admission policy; it does not itself create human membership,
   acquire a controller for another team or widen resource access. Human ID
   issuance and human team admission remain two approvals. Preserve the
   excluded token-route agent and existing artifact verification.
8. **Prove isolation, continuity and operation.** From each actual worker OS
   principal/container, demonstrate refusal of all protected key/unlock paths,
   inherited keychain access, mounts, debug/service-management interfaces and
   custody sockets. Show a permitted requester prepare/receipt, actual H
   LOGIN and separate UV approval, wrong-H/scope/credential refusals, blocked
   raw signing/export and stale/unknown authority. Prove the applicable real
   post-approval operation, not just a ready probe. Preserve receipt/history
   lookup after credential changes. Verify preexisting encrypted history,
   app data and allowed already-granted work. A path scanner's clean result
   is insufficient. Retain a discriminating negative control for each claim.
9. **Remove obsolete copies separately.** Only after every reader/writer uses
   the new boundary and read-back agrees, obtain approval to remove specific
   source copies/ciphertext fallbacks/environment entries and restart every
   process retaining them. Check internal resolver fallback paths, not only
   caller arguments. Deal with snapshots/WAL/backups under the approved
   retention policy. Never null a retired row with unresolved live authority
   or destroy a shared wrapping key to remove one encrypted value. Record
   removed and deliberately retained copy classes without recording secrets.

For every phase retain the approved plan hash and tool pin, source/target
public fingerprints and binding equality, supported operation/consumer version,
raw command exit, actual observed effect, refusal/control verdict, and residual
risk. `unknown` after a response loss is not permission to repeat import,
bootstrap, issuance or signing. Reconcile an immutable receipt/current state
through the original authority before any retry. A failed or incomplete proof
leaves the cohort unactivated or stopped; it is never relabelled protected.

## Backup, failure and rollback limits

| Point reached | Permitted recovery boundary | What it does not permit |
| --- | --- | --- |
| Before private import or reference writes | Abort the plan; retain existing custody/policy and evidence | Opting teams into the protected profile or changing H as a convenience |
| Private import/reference preparation only; no reader/policy cutover | Reconcile exact public equality and existing target; retry only through the reviewed idempotent/exclusive rule. A planned abort preserves the separately protected recovery copy | Overwriting a target, regenerating a key, assuming encrypted-row copies can be moved without purpose/row checks |
| Readers/policy cut over; old copies still retained | Restore only the explicitly tested schema/reader/policy combination within the protection boundary; stop writes if none exists | Returning keys/unlock material to workers or silently restoring legacy invite/bearer authority |
| Old copies/env entries removed | Recover only from the operator's protected same-key backup with matching bindings, authorizer/credential history and receipts; reconcile before resuming | Rolling back to readers that require removed ciphertext or restoring an old pending bootstrap over completed enrollment |
| Rotation, revocation or copy destruction separately performed | Follow that operation's reviewed recovery/continuity procedure and backup retention limits | Undoing revocation, restoring revoked sessions, promising ordinary migration rollback or reconstructing an erased key |

Back up the **protected signer database** and the separately protected offline
same-key recovery material with their exact compatible schema and public pins.
The database includes consumed bootstrap, authorizer/credential history,
operations, immutable receipts and audit. Encryption master/KMS access needed
to recover existing application data belongs to the recovery set without
becoming worker-readable. A successful backup is not a demonstrated restore;
record and test the restore procedure before claiming recoverability.

The current bundle's supported backup sequence is documented in
[OPERATIONS.md](../../deploy/team/OPERATIONS.md#backup):

```sh
deploy/team/teamctl stop deployment.yaml
deploy/team/teamctl backup deployment.yaml /private-backups/new-unique-directory
```

These are operator **mutations** requiring the appropriate deployment approval.
The command refuses running writers and external-PostgreSQL backup. Its archive
is credential-bearing and operator-only, while the live signer controller and
agent harness login are excluded. The offline controller backup is therefore
separate. With external PostgreSQL use its separately approved backup tools
at the same quiesced point; do not bypass the bundle refusal.

[Team restore is currently unsupported](../../deploy/team/OPERATIONS.md#restore-not-supported-for-a-teams-deployment).
The disposable-only `--lab-rehearsal` path cannot supply existing-customer
rollback proof. Binary downgrade does not undo migrations or policy changes.
Separate Logs purge-ledger and signer recovery qualification are prerequisites
where the affected state relies on them; source documentation is not a claim
that either runtime path is qualified. Never restore erasure tombstones or
bootstrap consumption backward to make a backup usable. The operator annex
must explicitly mark any unsupported restore case `no supported rollback` and
stop before an irreversible cutover without an accepted disposition.

## What an existing self-hosted/OATS owner runs

This is a staged upgrade of the existing service and state, not a fresh-team
onboarding shortcut:

1. Have the deployment operator inventory the configured OATS homes, roots,
   controllers and all member-admission clients. Resolve which keys are
   ordinary agent identity material and which confer controller/human powers.
   Keep service IDs/origins, the selected registry, actual agent IDs/keys,
   certificates, application installs/data and grants.
2. Select the exact supported protected host/profile and published compatible
   CLI/OATS/provider versions. Obtain the reviewed per-installation import plan
   and a separately chosen/proven H; absence of those is a stop, not permission
   to run `aw id human init`, `aw init` or create a new registry/root.
3. In the private operator environment, validate the public profile and perform
   the approved same-key team-controller import using the commands above.
   Namespace/human/legacy-root cases without a supported pinned importer stay
   blocked. Preserve the protected offline backup and stateful recovery plan.
4. Complete the approved H enrollment/association and protected service setup.
   The root's agent key remains with its actual runtime; it does not retain
   namespace/team-controller seeds. Configure the provider's exact protected
   service/root admission path. Reuse an eligible current registered root;
   obtain any necessary live root endorsement as a separate act. Do not
   replace an existing ancestry/head or excluded legacy root by relabelling.
5. Upgrade every affected client, then explicitly protect only the approved
   teams. Existing clients that need admission/renewal must use the configured
   service/root path. Clients cannot opt a team in just by upgrading. Existing
   signed artifacts remain verifiable; unattended worker governance cannot
   keep using a copied controller key in the protected profile.
6. Reuse compatible existing Secrets/Logs services and their nonempty databases.
   Add H's app owner/reader holdings only through the actual team-controller
   approval and membership checks, after H setup. Do not reinstall on empty
   databases to manufacture a successful migration. Verify the real permitted
   workflow, isolation and recovery evidence before removing source copies.

For the deployment owner the change is **where governance signing authority
lives and how approval/admission is requested**, not a new identity, new registry
or replacement team. Ordinary agent work remains within its existing rights;
protected governance needs the explicitly selected human and current policy.
The exact OATS setup/spawn command is supplied by package .7 for the selected
published version. This recipe does not invent an unimplemented OATS command
or equate a newly initialized deployment with migration of an existing one.

## Handback and release decision

The handback contains the public recipe's exact SHA, the private operator-plan
hash, inventory timestamp/limits, every class marked ready/blocked, explicit
consumer/package pins, supported tool names, rehearsal/control receipts,
backup/rollback limits, H choice and the per-action approval queue. Required
readers are the assigned security reader, naapp-review and the separately
accepted operator second reader. A coordination read or old inventory is not
that operator ACK.

The design can be reviewed while importers/catalog/restore tooling is still
missing. Its output must say **design ready; apply blocked** for those classes,
not turn missing tooling into automatic rotation, raw-key fallback or a blanket
production authorization. Operational locators and decisions stay with their
owning operator; they do not become part of this public contract.
