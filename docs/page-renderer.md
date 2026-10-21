# Shared page renderer (R1)

The renderer lives in `naapp-lib`, in `aweb_naapp.pages`. The Python hosting
helpers and packaged ES module are used unchanged by member and link hosts.
The frozen input contract is [aweb.page/1](page-format.md). This document
specifies the renderer adapter, not a new capability or authorization protocol.

## Host adapter

The host validates the full authorized snapshot with `validate_page_bytes` or
`validate_page` before passing it to `renderer.update(page)`. Authorization,
including page/row/field projection, happens before filtering or counting. Never
cache a snapshot across actors. A validation error is displayed through a safe
whole-page fallback, never by partially rendering an invalid known widget.

Serve the packaged `pages/assets/page-renderer.js` and `page-renderer.css` on the
host origin. `page_shell` supplies a shell and response headers; its `script_path`
selects the host's **external, packaged** entry module. That module imports:

```js
import { createPageRenderer, createLinkConfirmation } from '/assets/page-renderer.js';
const renderer = createPageRenderer({
  root: document.querySelector('#page'),
  destinations: document.querySelector('#destinations'),
  announcements: document.querySelector('#announcements'),
  host: adapter,
});
renderer.update(authorizedValidatedPage);
// Clear on logout, actor change, or lost authority, before any further read:
renderer.clear();
```

`destinations`, `announcements`, identity and approval chrome are host-owned
siblings outside `root`. No page content, styles or widget state can replace
them. All chrome, dates and numbers are English. The page's locale sets only the
page container's lang attribute for pronunciation; agent-authored text is never
translated. There is no locale switch. The host must supply trusted identity
and approval text itself. Link possession is not a verified human identity.

The host creates a native `<dialog id="link-confirmation">` outside `root`
(`page_shell` includes it), and supplies
`adapter.confirmLink = createLinkConfirmation(dialog)`. Page links have no
`href` or URL attribute; validated URLs stay in a renderer-owned WeakMap. A
trusted keyboard or pointer gesture opens the host confirmation, which parses
the URL independently and shows its normalized domain and full destination.
Cancel has initial focus; Escape cancels. Only the explicit Open gesture calls
`window.open` with `noopener,noreferrer`. The footer remains an index. Page
markup cannot create, restyle, remove or auto-trigger this host dialog.

The adapter grows with R1's widget slices. Its full shape is:

- `read({page_id, expected_page_rev, widget_id, bind})` resolves an authorized
  independent widget projection: `{page_rev, records, next_cursor, count}`. Every initial bound widget calls this, even with empty bootstrap records.
  Each record retains `{id, rev, value}`. A response at another page revision triggers a
  fresh full snapshot before it can be used, never mixing rows across revisions. Cursors are
  opaque; hosts bind them to actor, policy and query. Agent-defined filters, reader sorting and paging
  goes through this read; no broader collection is sent to the browser. The
  bootstrap retains only definitions and exact decision/bundle records required
  by the frozen validator.
- `actionPolicy(action_id, {widget_id, record})` returns trusted current
  `{allowed, reason, consequential, label, description, input}`. Missing policy
  disables actions. Page action definitions never grant permission. Consequential
  actions require `confirmAction`, created with `createActionConfirmation` over
  a host-owned native dialog outside the page (included in `page_shell`). This
  confirmation is a gesture, never human approval evidence.
- `csrfToken()` retrieves a nonempty host CSRF token through the host's private
  closure, separately for every state-changing callback. It is never a page value,
  DOM attribute or hidden input. Every submission captures its authority epoch and page before awaiting anything. Clearing the renderer fences the complete submission, including hashing, uploads, confirmations and refresh continuations; current policy is checked again before each dispatch.
- `refresh()` returns a newly authorized and validated full page, used for
  conflict recovery. The renderer refreshes in place, keeps the draft and offers Save my changes or Discard my changes. Saving explicitly rebases the revision; nothing retries silently.
- `formValues(widget_id)` optionally returns host-authorized current field values keyed by field ID. The host updates this cache before resolving `refresh()`. The renderer compares these with the edit baseline to mark fields changed concurrently, and uses them when the person discards a draft. It never infers current values from agent messages.
- `invoke(request, {csrfToken})` invokes an allowed action. Request context
  retains page/widget/action IDs, expected page and record revisions, an
  idempotency key, and typed input. Answer-kind actions are refused on this
  generic path; decisions use the dedicated `answer` adapter below. The
  host obtains `csrfToken` through its private adapter closure, never page JSON.
- `upload(request, {csrfToken})` applies the same authority/CSRF context and
  MIME/size bounds, returning attachment IDs. The submitted File is captured once and used for validation, hashing, metadata and bytes, even if the selection changes. Its request contains the `File`
  object and metadata including a SHA-256 binding in `input.file_sha256`; the
  host maps this to its declared upload tool, never an agent-supplied URL. The
  host validates actual bytes and MIME independently. Form file fields upload
  first, then submit attachment IDs through the typed action. Files never become
  agent URLs.
- `asset(asset_id)` returns a host-issued URL at `adapter.assetOrigin`, a
  separately pinned app asset origin. The renderer refuses any other origin.
- `health(subject)` returns an authorized, verified status-host projection:
  `{subject, reachable, observed_at, valid_until, reason?, fixing?}` with the
  [agent-health](agent-health.md) meanings. Report words are escaped and shown
  verbatim. Age and expiry are recalculated; missing, expired or mismatched
  evidence says Unknown. Presence never proves execution.
- `decision(task_id)` returns a trusted current read, independent of page JSON:
  `{task_id, task_rev, question_rev, status, allowed, authenticator,
  collection, record_id, record_rev, proposal_sha256, operation,
  source_version, expires_at, options, fields, application_state?, items?, answer?}`. `status` is `open`, `answered`,
  `pending` or `closed`. Only an open current question without a current answer
  can offer answer controls. `authenticator` is the policy-derived
  `member_session` or `passkey`, never the agent's choice. The host must enforce
  the required assurance, including passkey for external/irreversible operations.
  Each bundle item has `{record_id, record_rev, proposal_sha256}`, recomputed
  from the authorized current item in `items_collection`. All task/proposal,
  operation, destination, source and expiry bindings must match. The renderer
  also recomputes the displayed snapshot's C1 bundle/C2 proposal digests; this
  supplements the host's mandatory recomputation from its member-signed read.
  At apply time, the host re-checks the current proposal revision and recomputed
  digest, including every bundle item; a successful render-time check never
  substitutes for that check. The host validates raw JSON before supplying a
  snapshot: duplicate keys, non-integer numeric spellings and non-finite values
  cannot be recovered after ordinary JavaScript JSON parsing.
  `options` is the stored task's signed ordered `{value, label}` list; it must
  equal the page card's options canonically before any choices or values are
  shown. The host checks selected membership against that task list, never the
  page. `fields` is its signed ordered `{field, label, format}` list, with
  `format` in `text`, `date`, `number`, `money_minor`. Only those fields appear,
  with those labels and formats; schema titles never label a decision. Every
  field must exist in every verified item. Decision money requires an ISO 4217
  currency in the record and uses its scale in English; there is no symbol-less
  fallback on a decision. Browser display cases consume the canonical
  `decision-display-v1.json` directly.
  Proposal values are absent until the complete trusted read validates and are
  removed on failure. Invalid expiry is expired. A decision ignores every
  agent-authored widget-state message, progress and busy value, including live
  announcements. Its status comes only from the host-backed controller.
  A recommendation is advisory and no option is selected initially.
  Optional `application_state` is `pending`, `applied` or `failed`; only trusted
  `applied` is shown as Applied. A recorded approval is distinct from applying it.
- `answer({page_id, widget_id, action_id, task_id, stage}, {csrfToken}, event)`
  is the dedicated answer adapter, separate from `invoke`. The outer IDs are
  local routing context. `stage` has exactly `{expected_task_rev, choice, input,
  proposal_rev, proposal_sha256, answer_key}` as C2 defines. It has no page
  revision. `input` contains only additional values the person entered; a card
  without extra controls sends `{}` and visibly refuses a schema requiring
  fields it cannot collect. The host maps this call to the complete C2
  stage/task-answer/confirm flow, with verified current task receipts, policy,
  actor, exact proposal and atomic idempotency checks. A link is never approval.
  The trusted event may start an app-origin passkey handoff; proofs, challenges,
  links and credentials stay inside the host. Every state change requires host
  CSRF and the host's server-side Origin/session or capability validation.
  The callback returns the bound receipt `{task_answer_ref, task_id,
  question_rev, task_rev, proposal_rev, proposal_sha256, current: true, choice,
  approval_state}` only when the task answer is authoritative; `approval_state`
  may still be `pending`. A current receipt with matching task/question and
  proposal bindings is shown even after the task revision advances; revision
  growth alone is not evidence of an answer. A reopened question's older receipt
  is `current: false` and shown only as superseded. New answer controls always
  require an exact card/task revision match. A pending ceremony must not return a fabricated
  current receipt. The renderer distinguishes a recorded task answer from
  completed approval or execution, and never dispatches the operation itself.
  Lost outcomes lock the choice; an explicit retry reuses the same answer key
  and bytes after a fresh read. The unresolved attempt is retained privately by
  authority lifetime, page, task/question and proposal context across cosmetic
  widget replacements. A replacement cannot change its choice or key, and an
  outstanding call remains quarantined until reconciliation. `clear` or a new
  actor/page clears this private state; a different question or proposal never
  inherits it. Nothing is persisted in browser storage. Bundle decisions are one answer for all items,
  never per-item partial approval.

Actions fail closed if the adapter or CSRF is absent. Every state-changing
callback uses the host token before any signature or dispatch. Host adapters
must enforce Origin, session/capability authorization and CSRF server-side too;
the renderer cannot confer permission. C4's link secret exchange, ephemeral key,
nonce binding, expiry/revocation and one-use admission are outside this module.
Neither link secrets nor bearer capabilities enter a snapshot or renderer
request. C4 remains pending; these are local callback shapes, not a frozen wire
contract. Host approval adapters enforce member/passkey assurance; bearer links
never approve a member decision or external effect.

`update` must preserve unrelated local drafts, focus and scroll for the same
actor and page. Conflicts retain drafts and display an explicit recovery choice;
no silent retry overwrites another revision. `clear` discards drafts and content.
No browser storage is used to share drafts across actors.

## Local fixture gallery and browser tests

From the repository's `naapp-lib` directory:

```sh
uv sync --extra pages
npm ci --prefix renderer
npm run build --prefix renderer
uv run --extra pages python -m aweb_naapp.pages.gallery --port 8734
```

Open <http://127.0.0.1:8734/>. The separate asset origin uses HTTPS on port
8735 by default (`--asset-port` overrides it), with an ephemeral local-only TLS
certificate. For manual previews accept that local certificate once at the asset
origin so media can load. Browser tests accept only their disposable local TLS
fixture via Playwright's `ignoreHTTPSErrors`; applications use normally trusted
HTTPS assets. The gallery requires `openssl` and discards its key on shutdown.
Its synthetic sessions enforce Origin/CSRF, revisions and idempotency for the
renderer tests; these are fixtures, not application accounts or approval proof.
`Alt+u` commits a fixture state change and refreshes; `Alt+c` commits an unrelated
change without refreshing, to exercise conflict recovery. Neither GET consumes
an action. The browser runner uses ports 8740/8741, with `PAGE_GALLERY_PORT`
selecting another pair.
The gallery is a loopback fixture host with no real team credentials; its
packaged renderer is the same artifact consumed by applications. Widgets are
added to the gallery as their R1 slices land. Decision review cases include
`?case=decision-superseded`, `decision-reopened`, `decision-passkey-pending`,
`decision-approved`, `decision-rejected`, `decision-applied`,
`decision-apply-failed`, `decision-closed` and interactive `decision-unknown`.
The task's signed display metadata produces a Nightly price in the appropriate
currency, and `decision-options`, `decision-missing-field` and
`decision-missing-currency` expose refusal states. Full application authorization
and decision persistence are tested by their owners through the real Folio
stack, rather than simulated by this gallery.

`?case=authored-language` is a synthetic Catalan authored-content fixture:
the page title, paragraph and long form label/description use the page language,
while generated controls and English date/number formatting carry `lang="en"`.
It does not translate the product chrome or add a locale switch. Control
boundaries use `--page-control-border`, independently of neutral card borders;
hosts overriding it must retain at least 3:1 contrast against the control fill
and adjacent surface in both themes.

```sh
cd renderer
npx playwright install chromium
npm test
node build.mjs --check
```

The store/renderer preservation proof also uses disposable PostgreSQL databases
and a loopback HTTP host. It loads the packaged renderer, types an unsaved form
draft, commits an unrelated record through `PageStore.mutate`, and refreshes the
validated snapshot and per-widget projections. It asserts that the new record is
visible while the draft, focus, selection and scroll position survive. After
installing the browser dependencies above, run from the repository root:

```sh
AWEB_PAGE_STORE_BROWSER=1 uv run --project naapp-lib --extra page-store pytest -q naapp-lib/tests/page_store/test_renderer_browser.py
```

This test is opt-in because its Node/Chromium dependencies are installed separately
from the Python test dependencies. It starts its own server on a dynamic port.

Markdown uses [markdown-it](https://github.com/markdown-it/markdown-it) with raw
HTML disabled followed by a strict allowlist in
[DOMPurify](https://github.com/cure53/DOMPurify). DOMPurify owns the sole allowed
Trusted Types policy (`dompurify`). Other text uses text nodes; record values use
bidi isolation. Markdown images cannot load assets. HTTPS destinations are
normalized and shown in host chrome. Raw HTML/SVG remains literal text. The
shell enforces no inline/eval scripts, no frames, no referrers, no object/base
injection, and media restricted to the pinned asset origin.


## Accessibility verification

Browser tests cover keyboard link confirmation/cancellation, focus retained by
stable widget ID, polite state announcements, chart table alternatives, bidi
isolation and measured single-column phone geometry. Axe runs in light and dark
modes. E3 additionally checks real Windows typography and VoiceOver on macOS;
these manual passes require their actual platforms and are not replaced by a
browser user-agent override. English chrome is tested with non-English authored
content to ensure pronunciation metadata does not change the product language.


Image/video references are resolved by the host, checked against its separately
pinned HTTPS asset origin and rendered as image/video elements only. Video never
autoplays and has explicit native controls. No object, inline SVG or iframe can
render uploaded markup on the host origin. Captions and alternative text are
plain text. The asset host owns safe MIME, authorization, nosniff and restrictive
CORS/CSP for every request. `link_out` resolves only the frozen relative path
against the host's pinned app origin and uses the same host confirmation as
Markdown.

The browser form evaluator implements C1's bounded inline-schema subset without
an expression engine or code generation. Integer input must be safe and integral;
decimal strings are sent exactly, with no binary-float or locale coercion. Table
number formatting keeps decimal-string fractional digits. Stat string values
are authored display text; only integer stats are localized in English.


The local decision gallery is a disposable adapter-contract fixture, not a
production approval authority or passkey implementation. Production hosts must
implement C2's authenticated task-answer receipts and assurance checks. The same
packaged renderer is used unchanged for member and capability/link surfaces;
C4 adapters must provide the same verified reads, CSRF and answer contract,
without exposing link secrets or treating possession as human approval.
