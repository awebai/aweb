# Customer operations: draft and qualification matrix

This `aweb-acwd.7` runbook is a preparation draft. No row below has yet been
qualified against the complete landed, packaged BYOT lab. A procedure marked
**gap** is not a supported customer operation. A procedure marked **pending**
must be exercised on the identified landed components before support claims
or release approval. Do not substitute this draft for missing restore or
rotation tooling.

Read the [host configuration recipe](README.md), the
[release proposal](RELEASE.md), [acceptance map](../e2e/RELEASE.md) and
[Secrets design](../../../docs/design/secrets.md), especially §15 item 5.
The source inventory for this draft uses main `a0a71caef`, the reviewed D2
delta at `3d8933915`, and the Logs integration contract at `8f3ad5b5f`.
The latter two require landed receipts before execution. Logs packaging and
shared deployment configuration (`aweb-acwd.8`/`.9`) are further prerequisites.
These references describe source, not execution results.

## Access, evidence and support boundary

The customer's operator controls service accounts, databases, key custody,
backups, networking and the installed runner. Customer owners perform
governance through their actual authorized console/confirmation path. Logs
readers must be designated for the customer's team and sign in with a passkey;
a support identity, ordinary member or agent does not acquire read access.
Managed operation needs its own explicit customer authorization; possession of
this runbook or a diagnostic path does not grant access.

Support requests contain only component version/source SHA, artifact digest,
platform, custody mode, timestamps, public refusal codes, readiness/check
states, outbox age and needed non-secret correlation IDs. Do not collect
credential values, key material, private environment/config files, identity or
journal contents, registration codes, passkey assertions, delivered approval
links or raw HTTP/SMTP I/O. Receipt/event metadata can still reveal customer
activity: the customer chooses any authorized export and recipients.

An operator able to run code as Secrets can access plaintext during authorized
processing. In local-key mode, reading the key and stored ciphertext permits
full decryption outside application policy. KMS adds provider policy and an
independent audit trail; it does not make service operators unable to read
values. Describe those boundaries honestly when offering support.

## Health and delivery diagnosis

After configuring the actual service origins, use the release's supported
HTTPS routes with normal certificate verification. Do not disable TLS checks
or bypass Host routing to make a check pass.

| Observation | Interpretation and next action | Qualification |
| --- | --- | --- |
| Secrets `/live` | Process liveness; it runs no dependency checks. A 200 does not establish readiness. | Pending |
| Secrets `/health` and `/ready` | Inspect selected-provider, database and delivery checks. In D2, both origins and all three health routes carry `labels.custody_mode`. The legacy `checks.kms` slot checks the selected provider, including local-key mode. A failed check and its mode are separate facts. | Pending landed D2 and packaged lab |
| Secrets outbox age or stalled delivery | Use the owner audit-delivery view and the configured `hook_events_stalled_after_seconds` admission bound. Correlate target and event IDs with the receiver; do not delete outbox rows or treat retry as a new event. | Pending |
| Logs `/live` | Liveness only. | Pending |
| Logs `/ready` | Database and outbox query must answer. An old outbox does not itself make the current Logs readiness check fail. Inspect its age separately. | Pending |
| Logs `/health` | Always HTTP 200 with check detail; results are cached. A 200 alone is not a healthy dependency verdict. | Pending |
| Logs checkpoint failure | The periodic checkpoint loop logs its failure; it is not currently a readiness check. Escalate a sanitized failure/status and last successful checkpoint metadata. | Operational gap: no dedicated checkpoint diagnostic surface |

Native backend evidence is always split into `local_key_file` and `kms`.
Correct mode reporting while a backend refuses is useful failure evidence,
not a successful encrypt/decrypt or KMS execution result. A failed readiness
check is not fixed by changing its label or probing `/live` instead.

For a delivery incident, first identify the producer outbox event, the installed
receiver origin and the actual ingest result. Keep the existing signed event
and binding authority; do not replace the receiver with a newly installed
manifest or manufacture a receipt to clear a backlog.

| Logs ingest status | Public codes / meaning | Operator disposition to exercise |
| --- | --- | --- |
| 401 | `transport_certificate_invalid`, `transport_invalid_value` | Check the actual sender identity/certificate contract; do not bypass verification. |
| 403 | `binding_required`, `provenance_app_production`, `provenance_core_key` | Check installation, activated binding and provenance; this is not a transient successful delivery. |
| 409 | `event_conflict` | Preserve both event identity and existing receiver evidence; escalate the conflict. |
| 422 | `occurred_after_receipt`, `unknown_catalog` | Check version/catalog/time compatibility using metadata only. |
| 429 | `client_quota_exceeded` | Respect configured event/byte quotas and producer retry behavior. |
| 503 | `binding_authority_unavailable`, `chain_origin_mismatch`, `client_authority_changed`, `client_authority_unavailable`, `provenance_authority_unavailable` | Inspect authority, registry and configuration availability; producers retry these refusals. |
| 413 | Delivery exceeds the supported size | Pending the reviewed size-bound change; such delivery is unacceptable to the producer, not an ordinary retryable outage. |

All dispositions above are pending lab exercises. Do not infer the incident's
cause from an HTTP status alone; use its fixed code and correlated source and
receiver metadata.

## Backup and restore

**Gap: restore is not supported by this draft.** Secrets design §15 item 5
requires a destroyed-version tombstone list outside restorable content,
reapplied before a restored database serves, and a bounded backup-expiry
policy. The Logs owner identifies the external tombstone/restore foundation
as dependent on `aweb-acgg.13`. There is no exercised combined restore command
or procedure. A database restore without those controls must not be opened to
customer traffic.

Before a supported procedure can be approved, the operator must establish:

1. A consistent backup set for the databases, compatible source/schema versions,
   required custody keys and service-signing material, and retained public
   receipt/checkpoint keys. Key backups need at least the same access boundary
   as live keys. Do not place secrets in a release artifact or evidence bundle.
2. Independent tombstone storage and recovery, with reapplication completed
   before any restored service is admitted to traffic. Restoring a version that
   was destroyed must remain refused through the real service.
3. A concrete maximum backup lifetime and the resulting destruction-completion
   bound. Live deletion is not immediate destruction of decryptable backup
   copies. Do not invent a universal duration or promise erasure earlier than
   the customer's enforceable expiry policy.
4. Logs chain/epoch verification against receipts and checkpoints retained by
   readers or independent witnesses. An older backup can regress or fork from
   those witnesses. Never re-sign old history to conceal a restore mismatch.

The qualification must prove a successful authorized recovery and refusal of
resurrected destroyed data, not merely that PostgreSQL accepts a dump.

## Custody and signing-key rotation

**Gap: no customer custody-key rotation procedure is qualified.** Keep old key
material until a reviewed migration/re-wrap and recovery policy accounts for
every dependent record and retained backup. Replacing the configured local
key file, changing provider mode or changing a KMS identifier is not a data
migration. Do not recommend those actions as rotation commands.

Qualify KMS and local-key operations separately with actual pre-rotation
ciphertext, fresh writes, restart and backup compatibility. Record the provider
and the key/version metadata without key material. Provider-managed KMS key
rotation, moving to another KMS key, rotating a local custody key and changing
custody provider are different procedures; none inherits another's proof.

Logs uses the `logs-chain` key for both receipts and checkpoints. Its verifier
accepts sets of historical receipt/checkpoint keys, but that capability is not
an exercised signing-key rotation procedure. Preserve historical verification
keys and witnesses; no step may silently rewrite or re-sign the ledger.

## Upgrade and migration

**Pending.** Both apps run their pgdbm migrations at startup. Existing
migrations are never edited. Record the current schema/source/artifact identity
and take the supported protected backup before the upgrade; the backup/restore
gap above prevents promising rollback through a dump today.

The lab exercise must install a qualified prior release, create real state,
upgrade using the exact new digest/distributions, run migrations, and verify
existing authority, bindings, credentials, Logs chain/read access and runner
state. Check readiness and an actual broker/job/delivery/read journey. Record
the supported upgrade range. Binary downgrade is not a migration rollback;
there is no exercised rollback procedure in this inventory.

## Revoke, contain and rotate a credential

**Pending.** Use current owner authority and the existing confirmation paths;
support must not write application tables to simulate an owner act.

The lab exercises revoke/remove a real member through the owner controls,
show that member's next actual request is refused while an authorized member
still works, and correlate the resulting Activity/Logs evidence. Containment
must preserve the service's fences and original request/dispatch identity.
Credential replacement/rotation uses the supported value/reference change and
fresh approval flow; upstream credential revocation remains the upstream
owner's operation. Local refusal does not establish upstream revocation, and a
changed 1Password reference requires its genuine SDK/confirmation path.

External service outages, approval waiting, `outcome_unknown` and failed job
execution have distinct recovery/settlement paths. Retain their original IDs
and use the reviewed owner workflow; do not retry a possible external effect
as a fresh request to make an incident disappear.

## Audit access and export

Logs' integrated reader path is **pending landed integration and lab proof**.
A designated reader signs in on the separate console origin and reads its
team's `/v1/events`, `/v1/tail` and verification routes. An ingest receipt does
not qualify that read journey. Revocation must remove access to the existing
session under the real authority check.

**Gap: audit export is not supported.** Bundle-format/verifier work does not
provide an export endpoint or an `aw logs` command. Do not document either as
available. A supported export must later preserve ordering, chain/epoch and
receipt/checkpoint identity, verify the actual exported bytes, include a
tamper/refusal control and state redaction/retention limits. Customer approval
is required before sending an export to support or any outside recipient.

## Evidence matrix and completion

This matrix records requirements, not passes. Every pending row needs an exact
landed SHA, packaged artifact digest/checksum and platform, selected backend,
actual procedure/command, expected and observed outcomes, refusal/fault control,
and cleanup result. Keep separate KMS and local-key records even where a row's
logic is common. A missing backend run stays unqualified.

| Path | Local key-file | KMS | Required positive and failure evidence |
| --- | --- | --- | --- |
| Packaged startup, health and delivery | Pending | Pending | Correct build/mode/readiness; actual Logs delivery; selected-provider failure and stalled target |
| Backup/restore | Gap | Gap | Supported backup set, pre-serve tombstones, expiry bound, old data readable where authorized, destroyed data refused, Logs witnesses intact |
| Native custody rotation | Gap | Gap | Prior data and fresh writes after rotation/restart; wrong/unavailable key refuses; backup policy retained |
| Logs signing-key rotation | Gap | Gap | Historical receipts/checkpoints verify; new signatures verify; wrong key/reforged history refuses |
| Upgrade/migration | Pending | Pending | Prior-release state survives supported upgrade; authority/chain intact; incompatible schema/version refuses |
| Revoke/contain/credential replacement | Pending | Pending | Revoked principal refused; authorized neighbor succeeds; actual upstream/reference behavior and audit correlation |
| Reader designation and revocation | Pending | Pending | Delivered enrolment/login, scoped read, existing session loses revoked authority, outsider/agent refused |
| Customer audit export | Gap | Gap | Actual export endpoint/command, byte verification/order, tamper refusal and approved sharing |
| Sanitized support diagnosis | Pending | Pending | Needed failure diagnosed from codes/metadata; sensitive I/O/state excluded; unauthorized read refused |
| Runner restart and dispatch recovery | Pending | Pending | Same journal and actual pending result acknowledgment; real separate UID, signal/grace cleanup and pinned job success |

Logs retention/erasure/hold work on an unreviewed branch is not supported by
this runbook. The current default retains events; proposed purge metadata and
verification behavior must be reviewed, landed and exercised before inclusion.

The release owner requests R and Athena on the exact runbook/evidence head and
Logs review of its rows. Review of this draft does not close `aweb-acwd.7`.
The task remains open until supported paths have recorded lab evidence and
unsupported requirements are resolved or explicitly limited by the product
owner. Preparation can proceed before the release train; execution and
publication cannot use unlanded prerequisites as successful evidence.
