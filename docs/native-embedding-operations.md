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

## Message retention storage

`aweb.message_retention` owns storage eligibility. An operator supplies policy,
established ownership facts and an absolute UTC cutoff; these operations do not
enable automatic retention. Each sweep ends only its own team's interests.
Message visibility remains unchanged while any party retains an interest.

New mail/chat acceptance captures its native delivery/history parties as
`UNKNOWN` in the message transaction. Adding a readable history participant
adds an unknown party in that participant transaction. Captured parties survive
later participant retirement or succession. Legacy messages without complete
capture remain unknown; current membership cannot prove historical coverage.

`record_message_retention_owners(db, *, message, party_did, owner_team_ids)`
accepts a `MessageReference(kind, message_id)`, an actual recorded native party
and a nonempty frozen set of admitted canonical owner-team IDs established by
the host. It never infers billing ownership from an agent's current team. An
exact classification retry leaves interests unchanged. A different owner set
is an actionable conflict, retaining existing interests; transfer/renewal is
not implicit in incidental membership or key changes. Missing classification
does not reject an otherwise valid send.

`preview_team_message_retention(db, *, scope, limit=200, after=None)` accepts a
frozen `RetentionSweepScope(team_id, cutoff)`. Its cutoff must be timezone-aware
and no later than database transaction time. It returns a frozen
`MessageRetentionPreview` with a native preview ID, scope,
`mail_interests_expiring`, `chat_interests_expiring`, `mail_would_delete`,
`chat_would_delete`, `unclassified_retained`, `batch_count` and `next_after`.
All counts describe this bounded batch (maximum 1000 messages); pass
`next_after` as the next preview's `after` to continue. Preview expires no
interest and deletes no message. Its only write is a native receipt binding
the exact message/interest candidates and reported counts to this scope.

`apply_team_message_retention(db, *, preview)` requires that actual preview.
It checks the native receipt, locks/rechecks its candidates and returns
`MessageRetentionResult` with the preview ID and actual
`mail_interests_expired`, `chat_interests_expired`, `mail_deleted`,
`chat_deleted` and `unclassified_retained` counts. A forged/mismatched preview
refuses before effects and asks for a new preview. A completed preview retry
reports zero new mutations. When supplying a surrounding transaction, report
these effects as committed only after the outer transaction commits.

Physical deletion requires complete known party coverage, a nonempty explicit
owner set for every party, every interest ended and no pending native delivery
outbox obligation. Missing metadata, a new history party or a new unpreviewed
interest protects the row. Apply may delete fewer than previewed, never more:
even a row that becomes eligible after preview needs a new deletion preview.
It leaves participants, conversations/sessions and replay receipts intact;
only deleted chat messages' watermark references are cleared. No native
retention operation accepts a SQL predicate or a table-name argument.

The host reports the preview before requesting apply, rechecks its current
ownership/plan policy and keeps automatic retention off until its operator
separately enables it. A changed cutoff requires a new preview.

## Native resource lifecycle

`aweb.embedding.embedded_aweb(*, db_infra, redis, registry_client,
public_origin, mcp_factory, outbox_recovery, on_mutation=None,
rate_limiter=None, attachment_backend=None)` is an async context manager.
It accepts initialized structural database infrastructure (`is_initialized`
and `get_manager`), the host's Redis and configured registry clients, and a
synchronous factory returning the host's actual extended `ManagedMCPApp`.
These clients/pools remain host-owned and are never closed by this context.

The required `outbox_recovery` is `OutboxRecoveryOwnership.HOST` or `NATIVE`.
HOST starts no native recovery worker. NATIVE starts exactly one. The existing
`create_app(host_runs_outbox_recovery=...)` boolean remains accepted as a
compatibility adapter for standalone/library construction.

The context checks the complete native migration inventory and configured
registry, constructs one native federation authority and wake pair, then
invokes `mcp_factory(resources)` and starts that exact app's session manager.
It never substitutes a stock app for the factory's extended tools/custody.
The supplied mutation callback, limiter and attachment backend remain host
extensions. Standalone and ordinary library lifespans use the same native
resource owner and retain ownership of clients they themselves created.

The yielded `EmbeddedResources` holds `api_app`, `mcp_app`, `db_infra`,
`redis`, `registry_client`, `federation_authority`, `agent_wake_publisher`,
`agent_wake_hub`, `on_mutation` and typed `readiness`. Native state is installed
once. `native_resources(app)` reads the one typed `app.state.native_resources`
reference; a host may place that same reference on its root/wrappers rather
than copying native fields. The factory receives it after wake/federation
construction, so it can bind its actual extended app to those serving handles.

Startup failures raise `EmbeddingStartupError` with named
`ResourceStartupStage` and a safe actionable `NativeResourceReadiness` result;
the actual cause is logged/chained. Partial startup and shutdown unwind native
resources in reverse order. Readiness becomes unavailable when the native
context closes or its MCP/wake/recovery resource stops. An unavailable native
resource makes native `/ready` return 503 even if database/Redis still answer;
requests cannot restart the closed context's outbox worker.

Resource readiness does not establish mount readiness. The host mounts the
actual yielded handles under its auth/policy wrappers, verifies those actual
registrations and checks its additional dependencies before declaring the
deployment ready. MCP can remain a separate `/mcp` mount. Root federation
ingress can delegate the unchanged path to the same native API app:

```python
from starlette.routing import Route

host.mount("/api", resources.api_app)
host.mount("/mcp", resources.mcp_app)
host.router.routes.append(
    Route("/v1/federation/messages", resources.api_app, methods=["POST"])
)
```

That route uses the same native receiver, exception handlers and federation
authority as the API; it adds no second forwarding/validation implementation.
Host wrappers must preserve the external signed request path.

Native serving helpers follow that same reference for wake publication,
messaging runtime, origins, mutation callbacks and the existing identity-binding
cache. Hosts carrying the reference need no copied fields for those helpers.
States without a native reference retain their existing direct-field behavior.
Request verification remains with its common verification owner; a serving
resource reference never substitutes for a verified identity or request proof.
