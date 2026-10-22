# Typed records and collection tables

A Folio collection stores typed records. Agents add, patch, delete and query
records; people open the same authorized rows as a read-only table from the
team's Documents view. Status describes a recorded fact. It does not gate reading
or create an approval workflow.

The team installs Folio with `aw plugin install https://folio.aweb.ai`. An
existing install uses `aw plugin update folio` after a manifest change. Agents
use their existing team identities. The CLI and hosted MCP interpret the same
manifest tools and schemas.

## Callable tools

Every write takes a nonempty `request_id` (at most 128 characters). Collection
and record IDs are opaque strings, at most 128 characters. Request bodies cannot
supply a team, installation, principal or ACL.

Collection schemas must be object schemas with a `properties` map. Folio table
fields require schema objects; a `type` declaration, when present, must be a
single type name. Boolean property schemas and list-valued type unions
(including nullable unions) are refused with
HTTP 422 code `schema_invalid`. Optional fields can be omitted; optional text
can be cleared with `""`. This table constraint applies to definition and record
validation, without changing the shared C1 schema contract.

| Tool | Arguments | Result |
| --- | --- | --- |
| `collection-define` | `collection_id`, `title`, `schema`, `request_id` | `collection_id`, `schema_version`, `snapshot_rev`, `document_slug` |
| `record-add` | `collection_id`, `values`, `request_id`, optional `record_id` | `collection_id`, `record: {id, rev, value}`, `snapshot_rev` |
| `record-update` | `collection_id`, `record_id`, `expected_rev`, `patch`, `request_id` | Same shape as add |
| `record-delete` | `collection_id`, `record_id`, `expected_rev`, `request_id` | `collection_id`, `record_id`, `rev`, `deleted: true`, `snapshot_rev` |
| `record-query` | `collection_id`, optional `filter`, `sort`, `limit`, `cursor` | `collection_id`, `snapshot_rev`, `records`, `count`, `next_cursor` |

Omit `record_id` on add to let the server generate and return it. A caller may
supply a stable ID, such as a URL hash. Reusing an existing or deleted record ID
never overwrites a record.

Add validates the complete value. Update atomically merges only supplied fields,
validates the complete result and commits only if `expected_rev` matches.
Unmentioned fields survive. An optional text field can be cleared with `""`.
Invalid values or a revision conflict change nothing. A conflict is HTTP 409 with
code `revision_conflict`: reread, reconcile and use a new operation/request ID.

Within the retained replay window, retrying the identical operation and
`request_id` returns its original committed
result, including the generated record ID and original values, even after later
edits or deletion. Reusing that `request_id` with different input is refused. Delete has
the same replay rule. If permission has since narrowed, a retry may refuse rather
than reveal an old result the caller can no longer read.

Filters are ANDed: each is `{field, op, value}`, with `eq`, `ne`, `lt`, `lte`,
`gt`, `gte` or `in`. `in` takes up to 50 scalar values; other comparisons take a
scalar. There are at most 20 filters and eight `{field, direction}` sort entries
(`asc` or `desc`). Sorting has a stable record-ID tiebreak. `limit` is 1–200,
default 50.

`count` means **all matching authorized rows**, not the number of rows in the
current page. Filters, sorting, counts and pagination operate only on rows and
fields the caller may read. Pass `next_cursor` with the same query for the next
page. A page revision change or invalid cursor produces HTTP 409 code
`cursor_invalid`; restart without a cursor. `snapshot_rev` identifies the page
revision used by the shared store.

## First collection: discovery

Use `collection_id: "discovery"` and title **Discoveries and conversations**.

| Field | Type | Meaning |
| --- | --- | --- |
| `source_url` | Required text, 1–2048 characters | Safe HTTP(S) source, without embedded credentials |
| `date` | Required `YYYY-MM-DD` calendar date | Local America/Vancouver read/discovery date; do not invent a publication date |
| `finding` | Required text, 1–8192 characters | What was found or discussed |
| `why_relevant` | Required text, 1–8192 characters | Why it matters |
| `possible_contribution` | Optional text, at most 8192 characters | Possible contribution |
| `status` | Required text, 1–160 characters | What happened; arbitrary descriptive text |
| `next_follow_up` | Optional text, at most 8192 characters | Possible next follow-up |
| `kind` | Required `awareness` or `interaction` | Distinguishes discovery from conversation |

The definition uses a JSON object schema with those properties, the six required
fields above, and `additionalProperties: false`. Real calendar dates are checked
on complete records, including after a partial update; `2026-02-29` is invalid.
Unsafe source schemes and embedded credentials are refused. Clickable HTTPS
sources use the shared renderer's safe-link confirmation; HTTP and refused link
values remain inert. A source URL is never fetched by storing it.

For example, save an add body as `add.json`:

```json
{
  "collection_id": "discovery",
  "request_id": "discovery-example-add-1",
  "values": {
    "source_url": "https://example.com/research",
    "date": "2026-10-21",
    "finding": "A discussion about shared research records",
    "why_relevant": "It describes the same collaboration need",
    "status": "read; no contact yet",
    "kind": "awareness"
  }
}
```

Call `aw folio record-add --body-file add.json`, then keep the returned record
ID/revision. A one-field update supplies only the changed field in `patch`.

## Opening the table

`collection-define` returns a stable `document_slug`. The collection appears as
a table entry in the existing Documents list. Clicking it mints a fresh,
short-lived, read-only live link through the existing `present` tool. Agents can
also call `aw folio present --slug <document_slug>` for a usable URL.

The table view is labelled **Live**: its holders can see later-added rows within
the creator's current access until the link expires or is revoked. Current
creator membership, page/row/field access and deletion are checked on every use.
The table cannot edit records. Pagination stays within the link's collection and
field ceiling, with at most 200 rows per page and a cursor bound to that link
and creator. Empty collections open as empty tables.

A usable capability URL is never stored in an operation receipt. Deliberately
pinned snapshots retain their separate frozen semantics; the dashboard table
click is a live self-view, with no share-mode chooser.

After reloading a table page, open it again from the dashboard Documents entry
or the original link. The page explains this when its link is unavailable.
