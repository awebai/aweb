# Persistent naapp pages

Install `aweb-naapp[page-store]`. `aweb_naapp.page_store.PageStore` owns page,
record, schema and layout persistence. `aweb_naapp.pages` remains the frozen
`aweb.page/1` validator. Apps mount their own manifest tools over this API and
use the shared runtime verifier and admission fence first. Never deserialize a
caller-supplied `Principal`, `Access`, lifecycle hook or lifecycle authorizer as
authority. The host passes the current verified principal and installation scope
on every call, including reads and receipt retries.

Create separate pgdbm database managers for content and the deletion ledger.
Run `apply_page_store_migrations(content, ledger)`, construct the store, then
`await store.start()` **before admitting traffic**. Startup reapplies live ledger
tombstones to restored content and assigns a fresh UUID `restore_generation`.
Generation changes on every startup because a restore cannot otherwise be
identified reliably. Startup waits for in-flight content transactions before
advancing generation. Reads and writes independently check the ledger,
so an unavailable ledger cannot authorize access. The ledger must have independent
backup/recovery: never replace it with a content backup. All instances serving a
restored database must restart through this fence before serving page or asset
routes. Backup operation remains the operator's responsibility.

`NaappSettings.page_retention_policy`, configured with the JSON environment
setting **`AWEB_PAGE_RETENTION_POLICY`**, has no default. Construct
`RetentionPolicy(**settings.page_retention_policy)` only when it is present;
otherwise pass `retention=None`. Content creation, mutation, layout/schema/ACL
changes and portable import refuse with **503 `retention_policy_required`**
until an operator publishes an approved version. Reads, export and deletion
remain available. The separate ledger URL is
`NaappSettings.page_deletion_database_url` / `AWEB_PAGE_DELETION_DATABASE_URL`.

The required policy fields are `version`, `content_purge_days`,
`audit_content_days`, `backup_expiry_days`, `backup_interval_hours`,
`restore_rpo_hours`, `retry_horizon_days`, `encrypted_backups` and
`legal_exceptions`. Juan approved these production values on 2026-10-20: `content_purge_days=7`,
`audit_content_days=90`, `backup_expiry_days=30`, `backup_interval_hours=24`,
`restore_rpo_hours=24`, `retry_horizon_days=30`, and `encrypted_backups=true`. Primary page content is
purged immediately on request, within that deletion ceiling. Production must
explicitly set the approved policy/version and any disclosed
legal exceptions. The operator verifies backup expiry, restore objectives and
provider deletion coverage before enabling collection of business data. These
are operator values, never code defaults.
Call `enforce_retention()` from the app's existing worker scheduler. Missing
policy or outstanding legal retention prevents a deletion-complete claim.

`Scope` binds installation, team, app and page. The principal's verified stable
`did:aw` is used only when the shared verifier confirmed registry continuity;
otherwise the signed `did:key` is used. Stored `Access` defines the owner,
readers/writers, per-principal hidden rows and field sets. Authorization runs
before query predicates, sorting and counts. A field-hidden value cannot be
used as a filter or sort key. Unauthorized and absent pages share 404
`resource_not_found`. The host still checks current app/installation grants:
page ACLs cannot resurrect an uninstalled app.

An owner may explicitly grant `Access(team_id=scope.team_id, team_read=True,
team_write=True)`. Both flags default to false; `team_write` also permits reads.
The ACL is persisted on this page's full installation/team/app/page scope, and
its team ID must match. Public member paths check the verified principal's team
before consulting it; the host still checks current membership/certificate and
installation admission. Trusted creator-scoped link paths require the app's
checked current creator identity, not an anonymous caller's invented principal.
Per-principal hidden-row and field rules still narrow team grants. Team flags
never grant owner-only layout, schema, ACL, import/export or deletion authority.
Old stored ACLs without the flags retain their original named-member behavior.

`create`, `mutate`, `sync`, `migrate_schema`, `append_layout` and
`change_access` take an idempotency key. Changes require `expected_rev`; record
changes also require `expected_rev` on each row (zero for creation). A batch
is atomic. Owned records cannot use the sync path, and synced records cannot
use the ordinary edit path. Sync admission is owner-only and the host also
verifies the source adapter. Schema migration validates every retained row,
including rows past the first snapshot. Deleted record IDs remain tombstones.
There is no generic patch path to policy, provenance, revisions or schemas.

`mutate_on(tx, scope, principal, expected_rev=..., key=..., records=..., state=...)`
uses a caller-owned transaction from the content database. It applies the same
owned-record, field, revision and idempotency checks as `mutate`, so the caller
can join page effects and its own outbox or journal writes in one commit. The
caller commits or rolls back; a refusal rolls back the page changes to a
savepoint even when the caller catches it to record a failure. The independent
request claim survives a rollback and follows the same retry rules below.
An accepted retry returns the first receipt without rewriting the page. The
caller must also make its joined writes idempotent: key journal entries by that
receipt's `transaction_id`, and derive a distinct stable event ID for each
joined outbox event. The page-change event already uses the transaction ID.
The argument must be a pgdbm `TransactionManager`, not a database manager.
Locks remain held until the caller commits or rolls back. Make no network
calls between the mutation and the end of that transaction.

`create_on(tx, scope, principal, document, access=..., key=...)` uses the same
caller-owned transaction and savepoint rules for creation. Join app discovery
metadata in that transaction, using an idempotent insert keyed by page ID and
the returned creation receipt. A failed caller transaction rolls back both.

For row-local tools, `add_record(scope, principal, collection=..., values=...,
key=..., record_id=None)`, `patch_record(..., record_id=..., expected_rev=...,
patch=..., key=...)` and `delete_record(..., record_id=..., expected_rev=...,
key=...)` use the current page revision under its write lock. They require no
caller page revision; record update/delete still compare the supplied record
revision. The retry identity is the original add/patch/delete input, excluding
the derived page revision. A generated `rec_` ID is allocated only after the
claim, and a committed retry returns its original ID. Deleted IDs remain
unreusable tombstones.

Patches shallowly merge only supplied top-level fields. Omitted fields survive;
`null` is a value subject to the schema, and an empty patch is refused. The
store validates the whole merged record before committing. A writer may patch
an allowed field while other fields remain hidden and unchanged internally.
The returned durable receipt contains `record_id`, `rev`, the ordinary page
receipt, and for add/patch the original authorized `record: {id, rev, value}`;
delete returns `deleted: true`. Replays use that stored outcome even after later
row edits/deletion. Current row/field access is checked again: if the original
outcome can no longer be disclosed, the retry refuses with `action_denied`.

An app may supply `PageStore(..., record_validator=callable)` for its additional
value rules. After shared C1 validation, the synchronous trusted callable gets
`(scope, collection_definition, complete_record)`; the last argument is the full
record envelope, not just its value. It sees the whole merged record inside
the write and raises `StoreError("schema_invalid", details=...)` to refuse.
It must not mutate input, do network I/O or control transactions. The hook also
validates initial creation, sync, schema migration and portable imports. For
example an app can check real ISO calendar dates while C1's frozen `format`
annotations retain their existing meaning. No merge or ACL logic belongs in
that callback.

The content transaction writes data, audit, receipt and the shared outbox
together. The independent request claim commits first; a failed content
transaction leaves a recoverable claim rather than an invented success receipt.
Events contain only installation/app/page IDs, revision and deletion state.
The existing outbox drain owns delivery and retries; applications do not emit
before commit or copy the outbox primitive. Idempotency uses the shared store;
matching retries return the first receipt after current access is checked,
different bytes conflict, and expired keys never execute again. Live keys last
for the resource lifetime; deletion starts their configured retry horizon.
Request keys, canonical request hashes and transaction references are claimed
through the shared idempotency primitive in the independent ledger before any
content write. The claim records its content generation. A matching retry returns
the first receipt only when that transaction exists in current content. A claim
without a content receipt in the current generation can retry using the same
transaction ID: the failed attempt never committed. A claim without its receipt
from an older generation refuses with **409 `request_lost_in_restore`**, including
an uncertain pre-commit attempt across a restart. The caller re-reads and decides;
the old key never silently performs another mutation. A changed request under
the same key remains **409 `idempotency_conflict`**. Both ordinary and deletion
request keys survive content restore.

The renderer seam is `read(scope, principal)` for a validated bootstrap (empty bound collection records; exact decision/bundle
records retained as required by C1), and
`read_widget(scope, principal, widget_id=..., expected_page_rev=..., bind=...)`
for `{page_rev, records, next_cursor, count}`. Cursors bind principal, complete
scope, page/policy revision and query bytes. A changed page revision requires a
fresh snapshot. A cursor never grants permission. Widgets keep stable IDs;
layout edits append immutable versions and cannot change an existing ID's type.
Widget state accepts only `message`, `progress` and `busy`. Unsent form input,
focus and scroll belong to the renderer's local state. The host clears the
renderer before any actor or authority change.

`query_widget(scope, principal, widget_id=..., bind=...,
expected_page_rev=None)` uses that same query engine for admitted members. An
omitted revision selects the current page revision while holding its lock;
`read_widget` still requires the renderer's expected revision.

For caller-owned installation admission, use `add_record_on(tx, scope,
principal, ...)`, `patch_record_on(tx, scope, principal, ...)` or
`delete_record_on(tx, scope, principal, ...)`, with the same keyword arguments
and receipts as the standalone record methods. Each requires a
`TransactionManager` and uses a savepoint on its connection. The ordinary
record methods delegate to these paths. Page writes, receipts, audit and
outbox roll back with the caller; independent retry claims remain recoverable.
`query_member_widget_on(tx, scope, principal, widget_id=..., bind=...,
expected_page_rev=None)` reads uncommitted records on that same connection.
The host admits/checks the installation fence before page locks, and owns
commit/rollback. Make no network calls while these locks are held. These
member entry points require an authenticated admitted member; link holders use
the separately checked creator/projection path below.

`query_widget_on(tx, scope, creator_id=..., widget_id=..., bind=...,
link_id=..., expected_page_rev=None, projection=...)` serves a checked live link
on the caller's `TransactionManager`. The host supplies the verified link ID,
canonical creator identity and checked projection, and checks current creator
membership, session, revocation and expiry on every page. Missing projection
is refused. Hold the link lock until the query completes, with no intervening
network calls after acquiring the store's page lock.

The checked projection intersects current row/field ACLs in authorized SQL
before filtering, sorting, counting or pagination. `count` is the complete
matching authorized set, with at most 200 records per page. Checked-link
records contain exactly `{id, rev, value}`, excluding sync-source metadata.
Only this checked query path accepts `record_ids: "*"`, for live read-only grants whose minted
collection and fields remain fixed while rows follow current creator access.
Named lists remain literal, including `[]` for zero rows, count zero and no
cursor. Cursors additionally bind the link ID and complete checked projection;
they cannot cross links, creators or projection changes. A revision change
invalidates pagination and the host restarts from the first page. N5 refuses
dynamic-row grants with actions; writes keep their separate admission checks.

`read_projection_on(tx, scope, creator_id=..., projection=...,
expected_page_rev=None, source_snapshot=None)` loads bounded collection data on
the caller's content transaction and requires a pgdbm `TransactionManager`
before loading any data. The app supplies the creator's verified ACL
identity from its checked link context; it never constructs a member principal
for the anonymous holder. The app retains its link lock through loading the
view. The store also holds a page `FOR SHARE` lock until the transaction ends,
so the revision and current ACL remain stable while the projection is loaded.
Current row/field ACLs intersect the explicit named collection/record/field
projection; SQL uses the same authorized-record projection as widget reads.
Schema annotation redaction is shared with ordinary reads and exports.
Named row lists accept zero through 200 IDs. Empty means no rows; wildcard
markers are refused here and by both full-page pinned snapshot entry points.

The result is `{page_rev, collections: [{id, schema_version, schema, records}]}`;
each record contains only `id`, `rev` and its projected `value`. Assets are
handled separately by the app's asset adapter. With no source, values and
schemas come from the current page, and `expected_page_rev`, when supplied,
checks that revision. This is the live-read and mint-time data capture path.

With a stored `source_snapshot` in that result shape, the same projection path
uses its immutable values, schemas and revision, rechecking current page access,
deletion and row/field ACLs. `expected_page_rev` then checks the source revision.
The app must bind the source to the checked link scope and require it for pinned
mode; an absent or corrupt pinned source must never fall back to live values.
The input source is neither modified nor supplemented with current values.
This data projection returns only bounded collection data.

`capture_link_snapshot_on(tx, scope, creator_id=..., projection=...,
allowed_action_ids=..., expected_page_rev=...)` captures the complete authorized
`aweb.page/1` at mint. The same transaction and page lock cover the bounded
collection data, layout, widget state, collection modes and allowed action
definitions. The result passes the shared C1 validator, including widget,
depth, value and byte limits, plus C4's projection, 16-action and 64-asset bounds.
N5 stores it immutably with the link, revision and digest in that transaction.
The app adapter maps its checked `LinkScope` and creator to the store's scope
and ACL identity.

`project_link_snapshot_on(tx, scope, creator_id=..., projection=...,
allowed_action_ids=..., source_snapshot=..., expected_page_rev=None)` narrows
that complete stored page at use. The source is required, validated and bound
to the page ID; the app also binds it to the checked installation, team, link
and revision. Current page ACL/deletion checks and named row/field bounds apply.
An optional expected revision checks the source, not the current page. Neither
entry point commits or makes network calls; retain the caller's link lock
through all view loading.

Both paths use the ordinary store widget/schema redactor. Excluded widgets
become inert `access_unavailable` placeholders and lose their display state;
table/card action lists are filtered and only whitelisted edit/intent action
definitions remain. Edit actions also require current page write permission.
N5 supplies the whitelist after its current action-policy checks. Unknown
widget props are not retained in link views. Stored layout, state, schemas,
values and action definitions are never replaced with current versions or
widened by a newly allowed action. Host widget reads for pinned views must use
the stored source through `read_projection_on`, not live `read_widget`.

The projection's available asset IDs bound image/video widgets; losing an
asset replaces only that media with an unavailable placeholder. The page
contains asset IDs, never generated fetch URLs or grants. N5's asset adapter
owns immutable content-version resolution and retention references outside
the page, including release on revoke/expiry/purge and explicit deletion.

`lint_page(snapshot, allowed_actions=..., projections=...)` returns JSON-pointer
validation errors or accessible text: labels, values, state, policy-disabled
actions and unknown-widget fallback. Its projections must already be authorized.
It executes no Markdown, props, links, network calls or actions.

`export_page` is owner-only unless the host's current lifecycle authorizer grants
export; field/row restrictions still apply to that grant. `export_installation`
requires an explicit installation export grant and a grant for every page.
Archives carry a versioned manifest, revision cut, checksummed content and
artifacts, layout/schema history, provenance, redacted audit and unresolved
external references. The app's `LifecycleHooks.export` provides only accessible
tasks, answers, action/approval records and assets with checksums, excluding
signing keys, bearer links and other actors' private data. With no adapter,
external inventory is explicitly unresolved. Portable `import_page` requires
ACL mappings and validates content before activation. Imported historical
records are marked unverified; task decisions become inert and widget state is
reset. No capability, approval or pending external effect is rearmed.

`request_delete` durably records a job in the independent ledger, fences access,
purges local content and atomically queues the tombstone. The job records
`requested`, `access_revoked`, `purging`, `complete`. A crash after the ledger
commit leaves a fenced, recoverable job; startup and `advance_delete` reapply it.
The trusted worker calls `advance_delete(scope)` until coverage completes:

- `LifecycleHooks.revoke` revokes links and approvals and cancels undispatched
  requests, idempotently by job ID.
- `LifecycleHooks.purge` covers assets, derived caches/search, retained task
  references and reconciliation of dispatched external operations.
- `LifecycleHooks.backup_status` proves encrypted backup expiry and provider
  deletions. It must not claim completion while restorable content remains.

The hook receipts contain non-content references and coverage only. An absent
adapter, unresolved dispatched work, retained tasks, outstanding backups or
legal retention remains visible in `deletion_status`. Page erasure never claims
to erase another application's records. Deletion overrides routine audit-content
retention, retaining minimal non-content receipts and tombstones.

F2 CI and F3 certificate pagination remain production-enablement prerequisites.
The page-store tests use real PostgreSQL and real `pg_dump` / `pg_restore`
round trips while preserving the separate live ledger. They cover both lost
live-page mutations and surviving receipts, same-generation claim rollback,
concurrent retries, deletion recovery and restricted schema-history exports.
