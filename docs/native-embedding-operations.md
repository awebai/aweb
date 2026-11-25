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

`aweb.routes.agents.publish_encryption_key(*, db, payload, identity=None,
generation=None, agent_id=None)` accepts a
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

## Native resource lifecycle

`aweb.embedding.embedded_aweb(*, db_infra, redis, registry_client,
public_origin, mcp_factory, outbox_recovery, on_mutation=None,
attachment_backend=None, proxy_verification=None)` is an async context manager.
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

For a consumer that needs only the configured registry, use
`aweb.application_state.application_registry_client(request.app.state)`.
It returns the exact `RegistryClient` (including `CachedRegistryClient`)
selected by the native resource reference. A wrapper's other registry field
cannot override that reference. With no resource reference, the accessor uses
the initialized native `awid_registry_client` state slot, so a host can consume
this operation before converting its full native resource lifecycle.

The accessor constructs no transports, clients, caches or origins and performs
no health or registry read. Selecting configuration establishes neither
readiness nor request authority. Missing or invalid selected configuration
raises `RegistryClientUnavailable`, a `ServiceError` with `status_code=503`,
`code="registry_client_unavailable"`, `message` and the corresponding
`detail` dictionary. The native HTTP handler preserves that expected 503 and
its configure/start instruction; generic unexpected service failures retain
their existing masking. Hosted adapters preserve this refusal instead of
turning it into a negative grant or presence result. A missing resource client
never falls through to a wrapper's application-state client.

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

## Retained creation and verified generation

`aweb.routes.connect.PlannedIdentityIds(*, agent_id: UUID, workspace_id: UUID)`
is a frozen input to the existing keyword-only `connect_agent(...,
planned_ids=..., generation=...)`. The IDs constrain allocation and reuse;
they confer no authority. An exact retry returns those same resources. A
conflicting actor/workspace ID or cross-identity UUID collision raises
`PlannedIdentityConflict` (`planned_identity_conflict`, 409) and rolls back the
projection. Omitting `planned_ids` retains the constructor's existing
allocation/reuse behavior. No new HTTP request field or constructor is added.

`generation` is the actual `aweb.certificate_auth.VerifiedCertificateGeneration`
returned by `verify_certificate_generation`. Acquire it before opening the
projection transaction, using `CertificateAuthorityContext` with the serving
registry client, native database manager and configured TXT resolver. The
constructor reads its checked immutable claims and independently verified team
key directly; it neither reparses the artifact nor performs registry I/O.
Accompanying admission fields in `cert_info` or `team_did_key` cannot contradict
that proof. Global
identity/address and human-kind observations remain separate exact-subject
inputs; generation does not replace them.

Inside the projection transaction, generation admission locks and compares the
current admitted native team key before writing the member or workspace. A
controller move after verification refuses with `certificate_generation_stale`
and tells the caller to verify the retained certificate under the current key
before retrying. Existing request-certificate callers remain supported.

Mint bytes alone are pending material. With no current-controller proof, R27
retains the intended IDs/key/certificate and reports admission pending, without
calling the constructor or creating a native actor. With actual generation
proof, the one constructor can connect a working agent while its certificate's
registration remains pending. Registration completion is a separate outcome;
replay retains the exact signed artifact rather than minting another one.
These are the two outcomes ruled by Antares `0ffc3028` and `5cb50151`.

## Ordinary controller import

The same keyword-only `connect_agent(..., controller_import=member,
planned_ids=...)` accepts an actual
`aweb.controller_import.VerifiedControllerImportMember` from the fresh
`verify_controller_import` owner. See [checked team-control admission](team-control-admission.md)
for the shared signed selectors and owner-read snapshot. A batch or roster row
is not a constructor proof. Preview yields no member inputs; revoked rows are
planning data only. Unknown evidence raises a typed refusal and imports nothing.

This input is exclusive with generation. The constructor derives the exact
team/member/alias/scope/certificate and controller fields from the checked
member and refuses contradictory accompanying fields with
`controller_import_mismatch` and an action sentence. It rechecks original
request freshness after lock waits and compares the admitted controller under
the team lock before taking workspace locks and writing the member. A moved
key raises `controller_import_stale`; neither outcome commits projection
changes. Fresh global binding and kind observations retain their separate
owners. The checked import is never accepted as a request or generation proof.

Ordinary import always ensures a workspace. New resources use distinct planned
agent/workspace UUIDs and a manual workspace with empty host/path and no
repository. Reuse preserves the exact IDs, member name/role and workspace
profile/repository/kind/host/path. Without a new actual kind observation,
existing verified kind is preserved; an actual observation still governs its
projection. The Python result reports effective role, agent type and workspace
type. Host account/target authorization and operation completion remain in the
host's transaction. Import supplies no member artifact, fingerprint or new API
credential. Pending custodial activation still uses verified generation.

## Native application slots and the host resource reference

Hosts consume `native_resources(app)`. The native API still has initialized
application slots because its routes and shared dependencies read them. These
are references to the resources already created by the one lifecycle owner,
not additional clients or startup owners.

| Application slot | Native reader | Disposition |
|---|---|---|
| `db` | `deps.get_db`, `db.get_db_infra`, team-key pin and identity binding dependencies, health and outbox recovery | Retain for the native request and transaction scope. |
| `redis` | `deps.get_redis`, `redis_client.get_redis`, health, federation, dashboard and outbox recovery | Retain for native request dependencies and maintenance. |
| `awid_registry_client` | Team/identity auth, team-key pins, service registration, messaging and federation routes; `application_registry_client` also supports initialized servers without a resources object | Retain until those native readers consume the resource reference; a host wrapper does not create a shadow client. |
| `on_mutation` | `hooks.mutation_callback`, MCP callback scope, messaging runtime and durable federation replay | Retain the same callback reference for native producers/replay. |
| `federation_authority` | Native federation/contact routes and messaging runtime | Retain for the existing native route and transport owner. |
| `mcp_app` | No native route reads this slot; readiness and mounting use `EmbeddedResources.mcp_app` | This host compatibility projection is removed when the Cloud resource-reference consumer lands. Hosts use the typed reference rather than adding readers of this slot. |
| `agent_wake_publisher`, `agent_wake_hub` | `agent_wake.agent_wake_publisher`, `routes.events._agent_wake_hub` and shared wake cleanup | Retain for native wake publishing/subscription and the released manual wake-start API. |

`start_native_resources` writes six direct slots beside `native_resources`;
the shared wake starter writes the publisher/hub pair. `create_app` separately
initializes `proxy_verification`, `public_origin` and `attachment_backend`: native origin/signature
checks and participant attachment reads still require them. The source census at `0c2924fc5c` has native dependency
references in `deps.py:19`, `db.py:130`,
`team_key_pins.py:121`, `hooks.py:61`, `messaging/runtime.py:46`,
`routes/federation.py:377`, `routes/contacts.py:72`, `routes/events.py:888`,
`attachment_service.py:206`. Slot retirement must
convert those readers or preserve the released initialized-application path;
removing a host-only slot does not authorize removing native request state.


The `on_mutation` extension follows `aweb.hooks.MutationCallback`. Its
positional call returns an awaitable of `MutationDeliveryOutcome | None`.
The `attachment_backend` extension follows the
`aweb.attachments.AttachmentBackend` protocol.
The optional `first_contact_sender_policy` extension follows
`aweb.messaging.delivery_policy.FirstContactSenderPolicy`; its delivery rule
is in `docs/identity-messaging-contract.md`. The messaging runtime reads it
from the serving app state, then from the native app state.

## Existing-member certificate replacement

`aweb.certificate_projection.replace_member_certificate(*, db, agent_id,
team_id, member_did_key, expected_certificate_id, generation,
identity_binding=None)` updates an existing member without reconstructing its
profile or workspace. `generation` is the actual verified generation; it
supplies the checked artifact and independent current team key. The operation
locks team then member, checks the live exact team/key/alias/scope and expected
old certificate ID, and returns `CertificateProjectionResult` with
`UPDATED`/`UNCHANGED`, the same agent ID, certificate ID and proof fingerprint.
An exact already-applied generation is idempotent. A missing member, changed
fence or stale team proof is an actionable named conflict, never an UPDATE0
reported as success.

An omitted `identity_binding` asserts that signed identity claims equal the
stored verified binding, and the operation checks that assertion. If they
differ, the caller must supply an independently fresh matching native
`IdentityBinding`. The canonical `refresh_projection_binding` applies it in
the same transaction as the certificate acceptance; no intermediate mismatch
is committed. Without that proof, `certificate_binding_conflict` says what to
supply and nothing changes. An unchanged binding requires no fresh-registry
gate. Profile, role, kind, status and workspace fields remain unchanged. These
are Antares `16d02630`'s four required outcomes. Hosts can update their complete
artifact cache and retained operation in this transaction; native storage
never names those host columns.

## Requested workspace profile

`connect_agent` also accepts optional `workspace_profile` using
`WorkspaceProfile.MANUAL` or `WorkspaceProfile.HOSTED_MCP`. It is requested
metadata, not member authority. A supplied or existing repository keeps the
workspace kind `agent`; otherwise an explicit profile selects the non-repo
kind. Omission preserves an existing kind. The Python result includes effective
`workspace_type` so hosts do not read or rewrite native tables to discover it.
There is no second workspace constructor or added HTTP input/output field.

For retained admission completion, `publish_encryption_key` accepts
`generation=VerifiedCertificateGeneration` and `agent_id=UUID`, mutually exclusive
with `identity=TeamIdentity`. Pass the same open transaction used for
`connect_agent`; it retains the constructor's team and member locks. The public
member projection owner checks current eligibility and exact certificate/member/
controller equality. Only its verified stable identity is attributed to the
assertion. A manager alone is refused for this branch. The signed assertion
validator and storage remain shared with authenticated request publication.
Current request publication callers are the native PUT route and hosted service
publication; the new generation caller is hosted retained creation completion.

## Periodic maintenance

`aweb.maintenance.run_native_maintenance(*, db_infra, redis, registry_client,
on_mutation)` attempts outbox recovery and presence reconciliation once. It
returns `NativeMaintenanceResult(presence)` on success. On failure it raises
`NativeMaintenanceError` with named `failures` (stage and original error) and
`completed_stages`; the other stage is still attempted. Cancellation propagates.

Pass the exact serving `application_registry_client` reference. The native
serving timer invokes this operation; a HOST owner invokes it on its existing
maintenance schedule, retaining its released `outbox_recovery` operator name.
Presence runs without dashboard viewers, using the R15 transition owner and
R2's registry-aware grant validity. Runtime composition requires the complete
R2 Python component at `25e2229017`, rather than an old grant reader or a
missing-evidence fallback. Unknown grant authority cannot publish offline.

A mounted server whose first request starts automatic recovery still recovers
its outboxes if it lacks registry configuration: an explicit `None` reports a
named presence configuration failure after attempting recovery. It never
selects a shadow registry or marks presence healthy. Hosts with configured
resources pass their selected client. Resource ownership, borrowed connections
and cleanup remain with the existing lifecycle.

## Application-scoped proxy verification

`aweb.internal_auth.ProxyVerificationConfig` is a frozen keyword-only value:
`trust=ProxyHeaderTrust.DISABLED` or `SHARED_SECRET`, and
`shared_secret: str | None` (excluded from repr). Pass it as
`proxy_verification=` to `create_app`, `embedded_aweb`, `create_mcp_app`, or
`MCPAuthMiddleware`. `EmbeddedResources.proxy_verification` is the identical
object; an extended host MCP factory forwards it to the native middleware.
A host's signer/verifier must use that same captured secret. Cloud-specific
principal/selector authorization stays with its adapter; native MAC bytes and
native HTTP/MCP parsing remain shared.

Omitted configuration captures `AWEB_TRUST_PROXY_HEADERS` and
`AWEB_INTERNAL_AUTH_SECRET` once during construction. Enabled trust without a
nonempty secret raises `ProxyVerificationConfigurationError` with an action
sentence before serving. Configuration errors never include supplied values.
Request parsing does not consult environment, so later process changes and
another app's construction cannot change an existing app's verifier.

`parse_internal_auth_context(request)` selects the app's resource config before
any wrapper shadow; invalid resource configuration cannot fall through to a
host value. The native MCP middleware captures its explicit config at
construction, including when it is mounted under another app. Custom hosts
mounting only native routers can construct a config with
`ProxyVerificationConfig.capture()` and call its `install(app)` during app
construction, before exposing it. They do not write undocumented State fields.
An unconfigured custom router host has proxy trust disabled.

This changes no MAC preimage, accepted principal/actor fields or member check.
Hosts do not mutate/restore process environment to configure native serving.
Two independently configured native apps must reject each other's signed proxy
material; a failed third startup leaves both existing apps and process
configuration unchanged.

Retention `MessageReference` accepts the existing exact `"mail"`/`"chat"`
constructor strings and the canonical `aweb.messaging.kinds.MessageKind` values.
It stores the canonical enum while SQL and preview snapshots keep the same
plain wire strings. This changes no ownership, eligibility, preview/apply or
activation policy.
