# Native operations for embedding hosts

An embedding host owns its accounts, private material, policy, connections and
overlay data. Native mutations use the operations below rather than copying
server-table writes. These are in-process Python APIs. They do not establish
authority on their own; the caller supplies the already verified identity and
authorization required by the corresponding public protocol.

## First team admission

`aweb.team_admission.admit_team(*, db, team_id, team_did_key)` returns `True`
only when it inserts the native team row, and `False` when the admission
already exists. The namespace and team name come from the canonical team ID.
It leaves every existing identity field, key pin and accepted-act timestamp
unchanged. `connect_agent` calls this same owner inside its transaction.

This storage operation performs no registry lookup or authority verification.
Later pin movement stays with `AdmittedTeamKeys` and the
[team-key pin contract](trust-model.md#team-key-pins-approved-2026-11-12),
including its explicitly staged enforcement-off behavior. Invalid team IDs
give the caller an actionable canonical-format error.

## Migration application and readiness

`aweb.migrations.native_migration_modules()` returns an ordered tuple of frozen
`MigrationModule(module_name, migrations_path)` values: native core
`aweb-aweb`, then the hooks kit's `aweb_naapp_hooks`. The hook module owns the
owner-act nonce ledger. Both standalone initialization and host initialization
use this inventory; a host keeps its additional chains outside it.

`await apply_native_migrations(db)` returns frozen `AppliedNativeMigrations`
with an `applied` tuple of `NativeMigration(module_name, filename)` receipts.
It retains existing module identities, pgdbm checksums and locking. Retrying
after partial application applies only remaining files. It does not close the
host's pool or create its schema.

`await pending_native_migrations(db)` returns frozen `PendingNativeMigrations`
with a `pending` tuple of the same file identifiers, a `ready` boolean and an
actionable `message`. It checks the same inventory and applied checksums.
A schema with no migration ledger has every native file pending; the check
does not create a ledger. An unavailable database, missing package directory
or changed applied checksum raises `NativeMigrationError`, carrying
`operation` (`apply` or `check`) and `module_name`, with the real cause logged
and chained. Neither error nor pending work is successful readiness.

Run these operations against an initialized native database manager. A host
also checks its own chains and actual application/resource startup before
declaring itself ready. Native migration readiness alone does not prove that
an application is mounted or that host dependencies started.

## Contact acceptance and transfer

`aweb.messaging.contacts.ensure_identity_contact(*, db, owner_did,
contact_address, contact_did_aw, binding_controller_did, label="")` returns
the complete native contact view. `db` is a native manager or an open native
transaction. The caller supplies fresh independently resolved identity and
controller facts and the owner's explicit acceptance of a new contact.

A fresh row is active and carries that binding. A retry for the same accepted
stable identity returns the existing view without changing its status, label,
accepted controller or timestamps, including when fresh resolution names a
different controller for the unchanged identity. An existing unbound contact
or a different accepted stable identity is an actionable
`contact_identity_binding_required` conflict. It remains unchanged. Use the
existing explicit `bind_contact_identity` operation and its exact-old
acceptance contract for such a transition; an invitation retry cannot silently
bind, reactivate or replace an existing relationship. See
[identity and messaging](identity-messaging-contract.md#inbound-mode).

`transfer_contacts(*, db, old_owner_dids, target_owner_did)` returns frozen
`ContactTransferResult(moved, merged)`. The host selects predecessor owners
under its own account/identity authority. The native operation groups identity
references by address and handles by namespace/name, refusing differing
positive stable-DID bindings before any duplicate deletion. It chooses a
bound row first, an existing target-owner row next, and the lowest contact UUID
last. Every survivor field except owner remains unchanged. It performs no
identity resolution or acceptance of replacement bindings. `moved` counts
survivors whose owner changed; `merged` counts removed duplicates. A retry
after a completed transfer returns zero counts.

Both operations use a transaction or a savepoint within a supplied transaction,
so reciprocal contact changes and host bookkeeping can commit or roll back
together. A concurrent uniqueness conflict rolls back the transfer and asks
the caller to retry from current contacts.

## Encryption-key publication

`aweb.routes.agents.publish_encryption_key(*, db, identity, payload)` accepts a
native manager/transaction, an authenticated `TeamIdentity`, and the native
`EncryptionKeyAssertion` model. It returns `PublishEncryptionKeyResponse`.
The HTTP `PUT /v1/agents/me/encryption-key` route calls this same owner.

The caller obtains `identity` through native verification, including independent
global binding verification when applicable. The operation validates the
identity-signed assertion and its validity window, checks the exact live
team/member/key row, and persists the signed assertion. It stores no private
key material. Invalid assertions return an actionable 422
`invalid_encryption_key_assertion`; a missing live member returns 404 and asks
the caller to reconnect.

The identity signing key may renew a valid assertion under the same encryption
key ID with a new validity window. The custody and predecessor link remain
those of the signed assertion; no publication-intent bypass is needed. See
[assertion expiry and renewal](e2e-messaging-contract.md#assertion-expiry-and-renewal).
The host may include publication in its own native transaction so public
assertion and private custody bookkeeping fail together.

## Authored-mail existence

`aweb.messaging.mail_attribution.has_authored_mail(*, db, auth)` returns a
boolean from one native `SELECT EXISTS`. The caller authenticates and authorizes
the read first, then supplies its scoped native manager/transaction and
`MessagingAuth`. The operation uses only `participant_dids(auth)` with the
same native readable-mail and authored-identity predicates as ordinary reads.

Current signing-key evidence applies only inside a thread containing the
canonical participant. Predecessor attribution additionally requires both the
thread's succession receipt and its native predecessor-to-participant mapping.
Neither unrelated threads nor a predecessor's unthreaded mail gain authority.
The operation reads no bodies or custody material and propagates database
failures. It does not replace display/decryption or grant history access.
