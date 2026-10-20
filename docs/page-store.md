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
tombstones to restored content. Reads and writes independently check the ledger,
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

`create`, `mutate`, `sync`, `migrate_schema`, `append_layout` and
`change_access` take an idempotency key. Changes require `expected_rev`; record
changes also require `expected_rev` on each row (zero for creation). A batch
is atomic. Owned records cannot use the sync path, and synced records cannot
use the ordinary edit path. Sync admission is owner-only and the host also
verifies the source adapter. Schema migration validates every retained row,
including rows past the first snapshot. Deleted record IDs remain tombstones.
There is no generic patch path to policy, provenance, revisions or schemas.

The transaction writes data, audit, receipt and the shared outbox together.
Events contain only installation/app/page IDs, revision and deletion state.
The existing outbox drain owns delivery and retries; applications do not emit
before commit or copy the outbox primitive. Idempotency uses the shared store;
matching retries return the first receipt after current access is checked,
different bytes conflict, and expired keys never execute again. Live keys last
for the resource lifetime; deletion starts their configured retry horizon.

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
The page-store tests use real PostgreSQL and a real `pg_dump` / `pg_restore`
round trip while preserving the separate live ledger.
