# App usage reporting, `aweb.usage/1`

Status: **draft contract** (C5, aweb-acgg.11). It defines what an installed
app counts, how it reports those counts to its team server, how the team
server collects them without double counting or inventing history, and how a
team sees them. The design is [agent-pages.md](design/agent-pages.md) §8.

## Model

- **The app is the authority for its own usage.** Only the app sees every
  path into it: the CLI, hosted MCP, member surfaces, links, sync and
  background jobs. A transport-side counter cannot, so it is never the source
  of truth.
- **Usage is observation only.** Nothing in this contract denies, slows or
  prices anything. Safety limits stay security controls with their own
  outcomes (`safety_rate_limited`), and are counted as outcomes.
- **Reports are durable and exactly-once at the collector.** The app writes
  each usage entry in the same transaction as the operation it describes,
  then reports it until the collector acknowledges it. The collector
  deduplicates by report and by sequence, keeps gaps visible, and never fills
  them in.
- **Usage is not an app event.** It has its own purpose-bound credential,
  `app-usage`; an event credential is refused.

## 1. What is counted

Every quantity is a non-negative integer. **Counters** accumulate per entry;
**gauges** are absolute and may go down.

| Metric | Kind | Rule |
| --- | --- | --- |
| `calls` | counter | One per admitted API attempt: read or write, success, failure or no-op. A retry is another attempt (its own `attempt_id`) under the same `operation_id`. |
| `pages_created`, `pages_updated`, `pages_deleted` | counter | Committed page operations. One revision transaction is one update. |
| `page_reads` | counter | Accepted page reads. A re-render or refetch is a read, never a creation. |
| `records_created`, `records_updated`, `records_deleted` | counter | Committed rows affected. A batch reports each quantity, zero included, in one entry with `calls: 1`. |
| `record_reads` | counter | Rows returned after row and field ACLs, not rows scanned. |
| `intents_created` | counter | One per newly accepted intent. A retry, a task delivery or a notification is not another intent. |
| `intents_transitioned` | counter | One per intent state transition. |
| `decisions_requested`, `decisions_answered` | counter | Decision tasks created, and answers accepted, by the app. |
| `mails_sent` | counter | Notification mails the app actually sent. Counted, never limited (Juan's decision of 2026-10-19). |
| `pages_live`, `records_live` | gauge | Current inventory. |
| `bytes_live` | gauge | Canonical UTF-8 JSON bytes of current records, layouts and display state. |
| `bytes_versions`, `bytes_audit` | gauge | The same measure for retained history and audit content. |
| `bytes_assets` | gauge | Original object sizes of retained assets, each counted once per team. |
| `bytes_deleted_retained` | gauge | Bytes deleted but still retained, disjoint from every other byte gauge. |

"Canonical UTF-8 JSON bytes" is the length of the canonical JSON of
[app-task-requests.md](app-task-requests.md) for each stored value: no
database, index or physical overhead. Physical backup allocation is not an app
metric; an operator reports it separately with its attribution method.

**Outcomes.** Each entry carries one `outcome`: `committed`,
`idempotent_noop`, `read`, `refused_validation`, `refused_auth`,
`refused_policy`, `safety_limited` or `failed`. A refusal the app can
attribute to its installation is counted as a call with that outcome.
Unattributable hostile traffic is security telemetry, never team usage.

**Sources.** Each entry carries one `source`: `cli`, `mcp`, `surface`, `link`,
`sync`, `background`, `hook` or `lifecycle`. `lifecycle` is deletion and
export work the installation's lifecycle tools perform.

**What never appears in usage.** No record content, title, file name, query,
capability, token, link secret or actor name. Operation and attempt IDs are
opaque.

## 2. The app's ledger

- The app writes a usage entry in the transaction that commits the operation
  it describes. A read, or a refused attempt, writes its entry in the app's
  durable meter ledger. Either way the entry is durable before the response.
- **Reporter and epoch.** `reporter` names one source of reports within the
  installation, `^[a-z0-9][a-z0-9-]{0,63}$`, for example `primary`; most apps
  have one. `epoch` is a positive integer. A reset (a lost ledger, a restored
  backup) starts the reporter's next epoch, never a restart of the old
  sequence. A new installation starts its reporters at epoch 1.
- **Sequence.** Each entry has the next integer in its reporter's sequence for
  that epoch, starting at 1, with no gaps and no reuse.
- **Deletion.** Deleting a page or collection reduces the gauges and moves its
  retained bytes between the disjoint byte gauges. It never rewrites past
  counters.

## 3. Report batch

The app sends its ledger in batches, oldest first:

```json
{
  "format": "aweb.usage/1",
  "team_id": "backend:acme.com",
  "app_id": "pages",
  "installation_id": "inst_01JB…",
  "installation_generation": 3,
  "reporter": "primary",
  "epoch": 1,
  "report_id": "rep_000017",
  "first_seq": 41,
  "last_seq": 42,
  "metric_version": 1,
  "entries": [
    {"seq": 41, "occurred_at": "2026-10-20T10:00:00Z", "operation_id": "op_1", "attempt_id": "at_1",
     "source": "cli", "outcome": "committed", "deltas": {"calls": 1, "records_updated": 1}},
    {"seq": 42, "occurred_at": "2026-10-20T10:00:01Z", "operation_id": "op_1", "attempt_id": "at_2",
     "source": "cli", "outcome": "idempotent_noop", "deltas": {"calls": 1}}
  ],
  "inventory": {"at_seq": 42, "pages_live": 1, "records_live": 14, "bytes_live": 18230,
                "bytes_versions": 4100, "bytes_audit": 2210, "bytes_assets": 0, "bytes_deleted_retained": 0}
}
```

| Field | Rule |
| --- | --- |
| `format`, `metric_version` | `"aweb.usage/1"` and `1`. |
| `team_id`, `app_id`, `installation_id`, `installation_generation` | The reporting installation. They equal the credential's. |
| `reporter`, `epoch` | The reporter (§2) and its epoch, a safe integer of at least 1. |
| `report_id` | `^[A-Za-z0-9._-]{1,128}$`, unique per reporter and epoch. |
| `first_seq`, `last_seq` | `1 ≤ first_seq ≤ last_seq`, `last_seq - first_seq < 1000`. |
| `entries` | Exactly the sequences `first_seq..last_seq`, in order, each once. |
| entry `occurred_at` | RFC 3339 UTC, `Z`, second precision: when the operation happened, not when it was reported. |
| entry `operation_id`, `attempt_id` | Opaque, `^[A-Za-z0-9._-]{1,128}$`. |
| entry `deltas` | Counter metrics only (§1), each a safe integer from 0 to 2^53−1. An omitted counter is 0. |
| `inventory` | Optional: every gauge of §1, each a safe non-negative integer, and `at_seq`, the sequence the gauges are true after, with `first_seq ≤ at_seq ≤ last_seq`. |

Unknown fields are refused at every level. The collector refuses a request
body over 1 MiB (1,048,576 bytes) before parsing it (413). The field bounds
above keep every valid batch's canonical JSON below that: the largest one
possible is 876,901 bytes. Its digest, `report_sha256`, is the bare hex SHA-256 of
`"aweb.usage-report/1\n" || canonical_json(batch)`.

## 4. Credential, purpose `app-usage`

The app signs each report with a key its manifest declares for the
`app-usage` purpose. It is the app credential family of
[app-task-requests.md](app-task-requests.md) §2, with `auth: "app-usage"` and:

```text
Authorization: AWEB-App-Usage DIDKey <did:key> <signature>
```

The signed payload binds `aud`, `method`, raw `path`, `team_id`, `app_id`,
`kid`, `did_key`, `installation_id`, `installation_generation`, `body_sha256`
and `timestamp`, exactly as for `app-request`. An `app-event` or
`app-request` credential never passes the `app-usage` verifier, and an
`app-usage` credential passes no other: the verifier requires both the signed
`auth` value and the `AWEB-App-Usage` prefix. One key may declare several
purposes in `app_keys`; the credential, not the key, carries the purpose. A
key whose `app_keys` entry does not declare `app-usage` is refused. A revoked or replaced key is refused;
there is no grace period.

**After uninstall** the retired installation keeps a lifecycle reporting grant,
and nothing else:

- **Which key.** Only an `app-usage` key that was registered, and not revoked,
  under that exact `installation_id` and generation when the installation was
  retired. No key can be registered for a retired installation, and a
  revocation still ends a key at once. The collector finds these keys through
  a lookup that serves retired installations for this purpose only; the live
  installation lookup never does.
- **Which installation.** A report names the retired installation's exact id
  and last generation. If the team reinstalls the app, the new installation
  never accepts the old generation's reports, and the old one reports only
  through its own grant.
- **What it may report.** Every entry has `source: "lifecycle"`, `outcome:
  "committed"`, and deltas only in `calls`, `pages_deleted` and
  `records_deleted`. A batch may carry a terminal inventory snapshot. The
  collector refuses any other entry from a retired installation, and the
  whole batch with it (403 `scope_denied`).
- **When it ends.** At the earlier of the installation's lifecycle status
  reporting its deletion and export work complete, and 30 days after the
  installation was retired, so that a disposal that never completes cannot
  keep a credential alive. The app sends its terminal report, and holds the
  collector's ack, before its lifecycle status reports completion. After the
  grant ends the collector refuses the installation's reports (403
  `scope_denied`).
- It never restores normal app, event or request authority.

## 5. Collector: `POST /v1/apps/usage/reports`

The team server collects reports. A host that embeds the team server collects
through the same service, and presents the results (§6).

In one transaction, after verifying the credential and the batch (§3):

1. **Same report again.** If `(team_id, app_id, installation_id, reporter,
   epoch, report_id)` is stored: the same `report_sha256` returns the stored
   ack (200); a different one is 409 `usage_conflict`.
2. **Overlap.** If any of `first_seq..last_seq` is already stored for this
   reporter and epoch under another report, every overlapping entry must be
   byte-identical (its canonical JSON); then the overlap is not counted again.
   Otherwise 409 `usage_conflict`.
3. **Snapshot identity.** A snapshot is identified by `(reporter, epoch,
   at_seq)` and is immutable once stored. A batch carrying an identical
   snapshot changes nothing; one carrying a snapshot with other gauges under a
   stored identity is 409 `usage_conflict`.
4. **Store and apply.** A batch refused by 1–3 stores nothing, entries
   included. Otherwise store the report, its new entries and its snapshot, and
   add the new entries' deltas to the counters. A reporter's **current
   inventory** is its stored snapshot with the highest `(epoch, at_seq)`,
   compared epoch first: a new epoch's first snapshot replaces the old epoch's
   although its sequence is lower, and a delayed snapshot from an older epoch,
   or an older sequence, is stored but never becomes current. Return 201:

```json
{"report_id": "rep_000017", "report_sha256": "<64 hex>", "reporter": "primary", "epoch": 1,
 "accepted": [41, 42], "complete_through": 42, "missing": [], "current_inventory": {"epoch": 1, "at_seq": 42}}
```

`complete_through` is the highest sequence, in the batch's reporter and epoch,
with every sequence from 1 to it stored. `missing` lists the gaps above it as `[first, last]` ranges, at most 32
ranges. A batch beyond a gap is accepted and stored, and the gap stays visible
until a report fills it. A snapshot sets the gauges; it never creates the
counters of the missing entries.

The app retries a batch, with the same `report_id` and bytes, until it holds an
ack. A network failure never drops ledger entries.

## 6. What a team sees: `GET /v1/apps/usage`

Team owners and admins (team-auth) read their own team's usage. The host's
operator reads every team's through its own authorized tooling. Members get no
usage. The response is per app and installation:

```json
{"app_id": "pages", "installation_id": "inst_01JB…", "metric_version": 1,
 "reporters": [{"reporter": "primary", "epochs": [{"epoch": 1, "complete_through": 42, "missing": []}],
                "last_report_at": "2026-10-20T10:00:05Z", "lag_seconds": 4,
                "inventory": {"epoch": 1, "at_seq": 42, "pages_live": 1}}],
 "counters": {"calls": 2, "records_updated": 1}}
```

Inventory is shown per reporter, its current inventory (§5), never merged
across reporters into one installation-wide figure.

- `counters` sums every stored entry, filterable by `from`/`to` on
  `occurred_at`, `source` and `outcome`.
- An app that has never reported, or has gaps, is shown as incomplete, never as
  zero.
- `GET /v1/apps/usage/export?format=jsonl` returns every stored entry with its
  report and sequence, paginated, for the team's own records.

## 7. No economic enforcement

Until pricing is decided, no app built on this contract denies, slows or
degrades an operation because of a usage count, and neither does its host.
Existing economic caps are not part of this contract. Folio's free-tier caps
(`free_max_documents`, `free_max_versions_per_doc`, keyed on the team's
subscription tier) must be explicitly reconciled when Folio moves onto the
shared runtime (F5): removed, or kept by a recorded decision. This contract
neither inherits nor encodes them.

## Errors

| Status | Code | When |
| --- | --- | --- |
| 401 | (app credential messages) | The `app-usage` credential fails. |
| 403 | `scope_denied` | The installation is retired outside its lifecycle grant, or the key is not registered for `app-usage`. |
| 409 | `usage_conflict` | A known report with other bytes, or an overlap that differs. |
| 413 | `schema_invalid` | The request body is over 1 MiB. |
| 422 | `schema_invalid` | The batch fails §3. |

## Conformance vectors

- `docs/vectors/app-usage-credential-v1.json`: the `app-usage` payload,
  canonical bytes, signature and headers, and cross-purpose refusals.
- `docs/vectors/usage-report-v1.json`: valid and refused batches with their
  `report_sha256`, and ordered collector sequences (retry, conflict, overlap,
  gap and fill, out-of-order snapshot, reporter epoch) with the expected ack
  of each.

`aweb_naapp.runtime.usage` validates batches, computes `report_sha256`,
checks the lifecycle grant's batch rules and builds the `app-usage`
credential, and runs both files.
