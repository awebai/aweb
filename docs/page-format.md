# Page format: `aweb.page/1`

Status: **frozen contract** (aweb-acgg.7, C1). It promotes the page format of
the [agent pages design](design/agent-pages.md) (§2, §4 and §7) to a versioned
contract. A change that alters what an existing page means is a new major
version (`aweb.page/2`), never an edit to this one.

| Artifact | Location |
| --- | --- |
| JSON Schema (Draft 2020-12) | [`naapp-lib/src/aweb_naapp/pages/page-format-v1.schema.json`](../naapp-lib/src/aweb_naapp/pages/page-format-v1.schema.json) |
| Conformance vectors | [`docs/vectors/page-format-v1.json`](vectors/page-format-v1.json) |
| Reference validator | `aweb_naapp.pages` (`validate_page`, `validate_page_bytes`, `bundle_sha256`), installed with the `pages` extra |

A page is declarative data that a naapp returns and a host renders with the
shared renderer. An agent never supplies HTML, CSS or script. The naapp
authorizes every read and every action; nothing in a page grants authority.

## 1. Validation

A page is validated in three layers, in order. Validation stops at the first
layer that reports an error, so the schema never runs on a page outside the
host limits, and lint never runs on a page that fails the schema. Every error
is a `layer`, a stable `code` and the RFC 6901 JSON pointer of the offending
value. Codes are stable; messages are not part of the contract.

### Host limits (`limits`)

Checked iteratively, before any recursive validator sees the page.

| Code | Rule |
| --- | --- |
| `too_large` | More than 10 MiB (10,485,760 bytes) of UTF-8 JSON. |
| `not_json` | Not UTF-8 JSON. |
| `duplicate_key` | An object repeats a key. |
| `non_finite_number` | `NaN`, `Infinity` or a number that overflows to infinity. |
| `not_object` | The page is not a JSON object. |
| `too_deep` | A widget is nested more than 8 deep (a top-level widget has depth 1). The pointer is the first widget past the limit. |
| `too_many_widgets` | More than 2,000 widgets in the layout tree, containers included. Pointer `/layout`. |
| `too_many_values` | More than 1,000,000 JSON values in the page, counting the page itself and every container and scalar. Pointer: the page. Large collections paginate. |
| `too_deep_json` | Any value is nested more than 64 deep (the page object has depth 1). The pointer is the first value past the limit. |
| `unsafe_number` | Any number anywhere in the page, record values and inline schemas included, is a float or an integer beyond ±(2^53−1). Fractional values are decimal strings. The pointer is the first such number in document order. |

The widget limits are checked before the general depth limit.

### Schema (`schema`)

The page must satisfy the JSON Schema. Every schema error has code `schema`
and the pointer of the failing instance. Widgets are discriminated by `type`,
so an error inside a known widget points into that widget. Two schema rules
need care in every implementation:

- **End of input.** Patterns end with `(?![\s\S])`, not `$`. In Python `re`,
  `$` also matches before a final newline, so `"items\n"` would pass an
  identifier pattern. Vectors pin this.
- **`date-time`.** The page schema asserts this profile, not merely annotates
  it: `YYYY-MM-DDThh:mm:ss`, an optional fraction of 1–9 digits, then `Z` or
  `±hh:mm`. Digits are ASCII; `T` and `Z` are uppercase; seconds are 00–59 (no
  leap second), and the date and time must exist. Vectors pin each refusal.

### Lint (`lint`)

| Code | Rule |
| --- | --- |
| `duplicate_widget_id` | Widget IDs are unique across the whole tree. Pointer: the later widget's `id`. |
| `unknown_action` | Every action reference (row actions, card and list actions, button, file drop, form submit, decision answer) names a defined action. |
| `unknown_collection` | Every binding, decision-card `collection` and bundle `items_collection` names a defined collection. |
| `unknown_field` | Every bound field (table columns, card, list and timeline fields, chart `x` and `series`, stat and badge `field`, binding filters and sort) is a property of the collection schema. |
| `form_missing_required_input` | A form's fields cover every required property of its submit action's `input_schema`. |
| `answer_action_not_answer` | A decision card's `answer_action` is an `answer`-kind action. |
| `recommendation_not_option` | A decision card's `recommendation` is one of its option values. |
| `state_unknown_widget` | Every `widget_state` key is the ID of a widget in the layout. |
| `duplicate_collection_id`, `duplicate_record_id`, `duplicate_action_id` | IDs are unique within their scope. |
| `record_invalid` | Each record's `value` satisfies its collection schema. |
| `inline_schema_keyword` | An inline schema (a collection schema or action input schema) uses only the keywords in the table below. Any other keyword is refused, `$ref`, `$defs`, every combinator (`allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`) and `uniqueItems` included. With no references or combinators, the written schema is the whole schema, so its validation cost is computable statically. |
| `inline_schema_unbounded` | Every array schema (`type` includes `array`, or it has `items` or `minItems`) declares `maxItems`. Every object schema whose `additionalProperties` is not `false` declares `maxProperties`. Pointer: the schema missing the bound. |
| `inline_schema_cost` | The schema's cost is at most 10,000. Cost: each sub-schema counts 1 plus its `enum` length, multiplied by the declared `maxItems` or `maxProperties` of every `items` or `additionalProperties` applicator above it. Pointer: the inline schema's root. |
| `page_validation_cost` | The sum over collections of (records in the snapshot × schema cost) is at most 200,000. Pointer `/collections`. No record is validated when this fails. |
| `inline_schema_number` | `type: "number"` is refused. Float literals and unsafe integers in an inline schema are already refused as `unsafe_number`. |
| `inline_schema_pattern` | `pattern` and `patternProperties` are refused. A regular expression's work and dialect cannot be bounded portably (JSON Schema specifies ECMA-262, and backtracking engines can take exponential time), so inline schemas use `enum`, `const`, lengths and bounds instead. A linear-time, ECMA-compatible subset would be a later, explicit addition. |
| `inline_schema_invalid` | A collection schema or action input schema is not a valid JSON Schema 2020-12 schema (checked against the meta-schema). Pointer: the offending keyword. Checked only after the subset rules pass, and before any record is validated. |
| `inline_schema_depth` | Inline schemas nest at most 16 sub-schemas deep. Pointer: the first sub-schema past the limit. |
| `bidi_control` | No embedding, override or isolate control (U+202A–U+202E, U+2066–U+2069) in the title, any layout string (Markdown included), any `widget_state` string or any action label. Record values are data; the renderer isolates them instead. |
| `bundle_*` | The bundle rules in §5. |

Permitted inline-schema keywords, each for a reason a page needs:

| Keywords | Why |
| --- | --- |
| `type`, `enum`, `const`, `required` | Field types, closed choices and mandatory fields, as the base pages use. |
| `properties`, `additionalProperties`, `maxProperties` | Record and input objects. `additionalProperties` is `false` for closed objects, or a schema for a bounded map. |
| `items`, `minItems`, `maxItems` | Bounded lists, such as a bundle's item list. |
| `minLength`, `maxLength`, `minimum`, `maximum` | Bounds on strings and integers. Text fields and identifiers are bounded by length, since `pattern` is refused. |
| `format`, `title`, `description`, `default`, `examples`, `$comment` | Annotations only; none is asserted. |

**Validation cost.** The schema budgets bound the work of validating one value
to cost × a constant and a whole snapshot to 200,000 × a constant. The
value-count limit bounds the host checks, which are linear in the page's
values. The targets are under 50 ms per record and under 1 s per page on
ordinary hardware. In the reference validator, the worst shapes measured about
20 ms for one record and under 400 ms for a page at the schema budgets. A page
at the value limit took under 300 ms, and a refused 10 MiB page under 400 ms. An implementation checks each value's arrays and objects
against their declared `maxItems` and `maxProperties`, and an object under
`additionalProperties: false` against its declared property count, **before**
applying `items` or `additionalProperties`. Then applying the schema never
iterates past a declared bound, whatever order its keywords appear in. A value
that exceeds a bound is `record_invalid`.

A record's value is validated against its collection schema only when that
schema passes the inline-schema rules, the meta-schema and both budgets. In inline schemas,
`format` is an annotation only: it is never asserted, so it cannot make two
implementations disagree.

## 2. Page snapshot

A page is an object with exactly these fields:

| Field | Meaning |
| --- | --- |
| `page_format` | `"aweb.page/1"`. Any other value is refused; a renderer shows a safe whole-page fallback. |
| `page_id`, `owner`, `policy_ref` | Opaque identifiers (`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`), never names or capabilities. |
| `locale` | The page's content locale, a language tag of at most 64 characters. In-page chrome uses the member's locale setting, else this, else English. The passkey hand-off never uses it (design §7). |
| `title` | Plain text. |
| `rev` | Monotonic page revision: every committed transaction increments it, including state, ACL, action progress and deletion. |
| `layout_version` | The immutable layout version this snapshot renders. |
| `layout` | The widget tree (§3). |
| `collections` | Collection definitions and the authorized record snapshot (§4). |
| `widget_state` | Display overrides by widget ID: `message`, `progress` (0–100) and `busy`. State never changes bindings, actions, policy or input schemas. |
| `actions` | Action definitions: `id`, `kind` (`edit`, `intent` or `answer`), `label`, `input_schema`, `policy_ref`, and optionally `target`, `operation` and `requires_approval`. Layout references actions; it never carries policy. |

Unknown fields are refused in every known object. Every number in a page, in
any field, record value or inline schema, is a safe integer (at most 2^53−1 in
magnitude); fractional values are decimal strings. The limits layer enforces
this page-wide (`unsafe_number`). A stat `value` and a binding filter `value` are a
string, a safe integer, a boolean or null, or for `in` a list of at most 50 of
those.

## 3. Widgets

Each widget has `id`, `type`, an optional plain-text `fallback`, and `props`.
Bound widgets also have `bind`; containers also have `children`.

| Widget | Props (required in bold) |
| --- | --- |
| `text` | **`markdown`**: Markdown with raw HTML disabled. Raw HTML renders as escaped text. |
| `heading` | **`text`**, **`level`** 1–6. |
| `stat` | **`label`**, `field` or `value`, `unit`. |
| `status_badge` | **`label`**, **`tone`** (`neutral`, `info`, `success`, `warning`, `danger`), `field`. |
| `table` | **`columns`** (`field`, `label`, `format`: `text`, `date`, `number`, `money_minor`, `status`), `row_actions`. Requires `bind`. |
| `cards`, `list` | **`fields`** (display slot to field), `actions`. Requires `bind`. |
| `activity_timeline` | **`fields`**. Requires `bind`. |
| `chart` | **`kind`** (`bar`, `line`, `pie`), **`x`**, **`series`**, **`alternative`** (the text or table alternative). Requires `bind`. |
| `form` | **`fields`**, **`submit_action`**. A field has `id`, `kind` (`text`, `number`, `date`, `select`, `checkbox`, `file`), `label`, `required` and `description`. A `select` requires `options`; a `file` requires `accept` (MIME types) and `max_bytes`. There are no password fields. |
| `button` | **`label`**, **`action`**, `confirmation`. |
| `decision_card` | See §5. |
| `file_drop` | **`label`**, **`action`**, **`accept`** (MIME types), **`max_bytes`** (at most 10 MiB). |
| `image`, `video` | **`asset_id`**, **`alt`**, `caption`. Assets load only from the app's asset origin, never inline in the host origin. |
| `agent_presence` | **`subject`**: rendered from published health evidence and its age, never a guessed indicator. |
| `link_out` | **`label`**, **`path`**: see §6. |
| `stack`, `grid` | Containers: `gap` (`small`, `medium`, `large`) and, for `grid`, **`columns`**. They collapse at phone width. |

**Bindings.** `bind` names a `collection`, an `all` list of at most 20
`{field, op, value}` filters (`eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`), an
ordered `sort` of at most 8 `{field, direction}`, a `limit` of 1–200 and an
opaque `cursor`. Fields are literal property names; there are no expressions,
paths or queries. The naapp applies row and field ACLs before filtering,
sorting or counting, and returns only authorized rows.

**Unknown widgets.** A widget whose `type` this version does not define needs a
`fallback`. It may carry `props` of at most 32 properties, which the renderer
never reads, so an older renderer accepts a newer widget. It renders as an
inert placeholder showing the fallback, with no children, network or actions.
A known widget with invalid props is a schema error, never treated as unknown.

## 4. Collections and records

A collection has `id`, `schema_version`, an inline JSON Schema `schema`,
`mode` (`owned` or `synced`) and `records`, at most 200 per snapshot. A record
has `id`, `rev` and `value`. A synced record also carries `source`: `system`,
`external_id`, `version` and `synced_at`. Inline schemas (and action input
schemas) follow the subset in the lint rules: allowlisted keywords only (no
references or combinators), declared bounds on every array and open object, a
cost within budget, no `number` type, no `pattern` or `patternProperties`,
bounded depth, and valid under the 2020-12 meta-schema.

## 5. Decision cards and bundles

A `decision_card` renders an acah.4 task. Its props are `task_id`, `task_rev`,
`collection`, `record_id`, `record_rev`, `options` (at most 10 `{value,
label}`), `recommendation`, `answer_action`, `proposal_sha256`, `operation`
(`kind`, `destination`, `summary`), `source_version` and `expires_at`. The
task answer is authoritative; the recommendation is advisory.

A card with `bundle: true` approves an ordered batch all or nothing. It must
also name `items_collection`. Its `record_id` and `record_rev` name a bundle
record in `collection` whose value is exactly:

```json
{"items": [{"record_id": "week-43", "record_rev": 2, "proposal_sha256": "sha256:<64 hex>"}]}
```

- The card's `proposal_sha256` is `"sha256:" + hex(SHA-256(b"aweb.page-bundle/1\n" + C(items)))`,
  where `\n` is a literal newline and `C` is canonical JSON: sorted keys, no
  insignificant whitespace, UTF-8 without escaping non-ASCII, safe integers
  and no floats. `bundle_hash` vectors pin it.
- Each item's `record_id` is an identifier, its `record_rev` a safe
  non-negative integer and its `proposal_sha256` `sha256:` plus 64 lowercase
  hex digits. A record appears at most once.
- A bundle holds 1–64 items, and the snapshot carries the bundle record and
  every item record.
- Each item names a record in `items_collection` at its current revision.
- Per-item accept, change or reject happens before the bundle is hashed. A
  change after hashing makes a new bundle and needs a new approval, never a
  partial approval.

| Code | Rule |
| --- | --- |
| `bundle_record_unknown` | The bundle record is not in the snapshot. |
| `bundle_record_mismatch` | The bundle record's revision differs from the card's `record_rev`. |
| `bundle_record_shape` | The bundle record's value is not exactly an item list of well-formed items. |
| `bundle_empty` | The item list is empty. |
| `bundle_too_many_items` | More than 64 items. |
| `bundle_duplicate_item` | A record is listed more than once. Pointer: the later item. |
| `bundle_item_unknown` | An item's record is not in `items_collection` in the snapshot. |
| `bundle_item_mismatch` | An item's record is at a different revision than the bundle binds. |
| `bundle_hash_mismatch` | The card's `proposal_sha256` is not the bundle hash. |

The host also refuses to show an answerable card when any item's current
revision or digest differs from the bundle (design §4).

## 6. `link_out`

`link_out` opens the installed app's own pinned origin and nothing else (Juan's
ruling on D1). `path` is a relative path only: it starts with `/` and consists
of segments of `[A-Za-z0-9._~-]`. It has no scheme, host, userinfo, query,
fragment, percent-encoding, backslash or `.`/`..` segment, so no page can carry
a token, capability or other destination in it. The host resolves the path
against the installation's pinned origin, which comes from the installation
and never from page data. It shows the normalized domain and opens a new
top-level context with no opener and no referrer.

## 7. Renderer obligations

Structurally valid pages can still carry hostile text. The renderer (R1) must
meet every `render` expectation in the vectors:

| Expectation | Obligation |
| --- | --- |
| `link_inert` | Links whose scheme is not https, after entity and percent decoding and whitespace removal, have no active destination: `javascript:`, `data:`, `vbscript:`, autolinks, reference links and image sources included. |
| `html_inert` | Raw HTML, SVG included, renders as escaped text. |
| `destination_domain_shown` | The normalized destination domain of every link is shown in host chrome. Display text and homoglyphs cannot hide it. |
| `bidi_isolated` | Bound record values are isolated, so bidi controls cannot reorder surrounding text. |
| `asset_origin_only` | Assets load only from the app's asset origin. |
| `text_escaped` | Plain text renders verbatim as text. |

Rendering also follows the design's origin rules: a Trusted Types policy owned
by the shared sanitizer, a host CSRF token on every state change, and host
approval and identity chrome outside the page container (design §7).

## 8. Conformance

An implementation conforms when it reaches every vector's verdict and reports
every expected error at its layer, code and pointer, and when it computes every
`bundle_hash` vector exactly. Reporting further errors in the same layer is
allowed. The vector file and this document change together, and the reference
validator's tests consume the root vector file directly.
