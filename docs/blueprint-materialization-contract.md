---
title: "Blueprint materialization contract (import-payload v1)"
kicker: "Contract SOT — DRAFT for sign-off"
description: "The one contract that aw and library both implement: profile/blueprint payload shape, the canonical digest, the public catalog response, materialization semantics, and the home pin. Materialization is a public read; the shelf is a separate opt-in app."
weight: 27
---

# Blueprint materialization contract (import-payload v1)

Status: **SIGNED OFF** (2026-07-02) by `atext.aweb.ai/coordinator` as
seed-catalog owner and for the library side (the library service is that team's
code). Hardened with `aw-reviewer`'s pre-implementation review. Tracked as
`default-aaeq.1`. The library-side symlink rejection is `default-aaeq.8`.

This is the single normative contract that **both** the `aw` CLI and the
**library** service implement, so an agent home materialized from a public
blueprint is byte-for-byte reproducible and provider-agnostic. It codifies the
shapes and algorithm both sides already run today (verified 2026-07-02); the few
**NEW** requirements below are marked as such.

Scope: the **public, unauthenticated** read of a blueprint profile and its
materialization into an agent home. The team **shelf** (import-to-shelf, bind,
propose/approve, refresh-from-shelf) is a separate opt-in app and is out of
scope here except where it reuses this payload shape (§7).

## 1. Versioning

The contract version lives in two payload **schema strings**, embedded in the
hashed payload so they are pinned by the digest itself:

- `aweb.blueprint.import-payload.v1` — a whole blueprint (blueprint.yaml +
  `profiles/<id>/...` for every profile).
- `aweb.blueprint.profile-payload.v1` — one profile's files, profile-relative.

There is no separate `schema_version` field on the wire. A consumer that does
not recognize a schema string MUST refuse to materialize. A breaking change to
any shape or to the digest algorithm is a new schema string (`...v2`), never an
in-place change to v1.

## 2. Payload shapes

### 2.1 File entry

Every file in a payload is exactly:

```json
{ "path": "<posix-relative path>", "content_utf8": "<file text>", "sha256": "sha256:<hex>" }
```

- `path` is a **normalized POSIX-relative** path to the payload root (profile
  root for profile-payload, blueprint root for import-payload). It MUST be
  non-empty and already clean: forward slashes only; no leading `/` (absolute),
  no `.` or `./` segments, no `..` segment, no repeated `//` separators, no
  trailing slash, no backslash, no NUL, no control characters, and no
  scheme/host (`://`). A path that is not already in this normalized form is
  rejected — the consumer does not silently normalize it.
- **Paths are unique.** Two entries with the same `path` are an ERROR; the
  payload is rejected before any digest or write. (Otherwise the digest would
  hash both while materialization overwrites one — ambiguous and
  non-reproducible.)
- `content_utf8` is the file's full UTF-8 text. The field is named
  `content_utf8` (not `content`).
- `sha256` is `"sha256:" + lowercase_hex(sha256(raw_utf8_bytes))` of that
  file's content.

### 2.2 Profile payload (`profile-payload.v1`)

A profile payload is the file set under one `profiles/<id>/`, path-stripped to
profile-relative. `profile.yaml` MUST be present. `profile.yaml` fields:

- required: `id` (becomes `profile_ref`), `version`;
- descriptive: `name`, `mission`, `accepted_work[]`, `runtime_assumptions[]`,
  `runtime_hints[]`, `memory_policy{}`, `expected_apps[]`,
  `event_subscriptions[]`, `approval_required[]`;
- materialized assets: `instructions` (path), `skills[]`, `artifacts[]` (each
  `{path, kind}`).

### 2.3 Blueprint payload (`import-payload.v1`)

A blueprint payload is `blueprint.yaml` plus every `profiles/<id>/...` file,
blueprint-relative. `blueprint.yaml` declares `id`, `name`, `version`, and
`profiles[]` (each `{id, default_count}`).

## 3. Canonical digest (normative, byte-exact)

Both a profile digest and a blueprint digest are computed identically, differing
only by schema string and the file set (profile-relative vs blueprint-relative):

1. **Collect files.** Walk the payload root. Include every regular file.
   **Exclude** these directory names anywhere in the tree: `.git`, `.hg`,
   `.svn`, `node_modules`, `.cache`, `dist`, `build`, `target`, `tmp`,
   `vendor`, `__pycache__`.
2. **NEW — symlinks (walk order is normative):** the symlink check happens per
   visited entry, **before** the excluded-directory skip. Consequences:
   - The excluded-directory entry itself is checked for being a symlink; if it
     is a real directory its **contents are never walked**. So a symlink
     **nested inside an excluded directory is never visited and is ACCEPTED**
     (it contributes nothing to the digest — e.g. `node_modules/.bin/*` in a
     real JS project).
   - A symlink at **any visited entry is an ERROR** — including a symlink whose
     own name matches an excluded-directory name, because the symlink check
     precedes the skip-by-name.
   This matches aw's `canonicalPayloadDigest` (blueprint.go:903 symlink check
   precedes the :907 excluded-dir skip), which is correct on the merits. The
   library MUST match it — today the library follows symlinks. Tracked as
   `default-aaeq.8`.
3. Build each file entry per §2.1. **Sort the entries by `path`** (ascending,
   byte order).
4. Build the payload object `{ "files": <sorted entries>, "schema": "<schema string>" }`.
5. **Canonical JSON bytes:** recursively sort object keys; separators `","`
   and `":"` (no whitespace); do **not** escape HTML; emit UTF-8.
   **NEW — U+2028 / U+2029:** file content MUST NOT contain the Unicode line
   separators U+2028 or U+2029. (Go's encoder escapes them even with HTML
   escaping off; Python emits them raw — a canonical-bytes mismatch. Forbidding
   them keeps both encoders byte-identical. A payload containing them is
   rejected.)
6. **Digest string:** `"sha256:" + lowercase_hex(sha256(canonical_bytes))`.

This algorithm is already implemented identically on both sides and the digests
match; this section freezes it.

## 4. Public catalog response (materialization input)

`GET {library-url}/v1/blueprints/{blueprint_ref}/profiles/{profile_ref}` —
**auth:none**, public. The response is **self-sufficient for materialize + the
profile pin**:

```json
{
  "blueprint_ref": "aweb.team",
  "blueprint_version": "0.1.0",
  "profile_ref": "developer",
  "version": "0.1.3",
  "digest": "sha256:<profile digest per §3>",
  "files": [ { "path": "...", "content_utf8": "...", "sha256": "sha256:..." }, ... ],
  "name": "...", "mission": "...", "runtime_assumptions": [...], "runtime_hints": [...], ...
}
```

- `digest` is the **profile** digest (§3, `profile-payload.v1`). It is the
  integrity anchor for materialization.
- **Decision (v1): the response carries no blueprint digest.** Blueprint
  provenance is `blueprint_ref` + `blueprint_version` only. A blueprint digest
  is not needed to materialize or refresh a single profile; if full blueprint
  provenance is wanted later, add an optional `blueprint_digest` field — a clean
  additive change, not a v1 requirement.
- **Ref resolution is first-publisher-exclusive (consumer guarantee).** A
  `blueprint_ref` resolves only to its first publisher's live catalog row, and
  the `aweb.*` namespace prefix is first-party-reserved. A deleted first-party
  ref returns **404** and is never remapped to another publisher — publish-side
  reservation guards prevent a squatter from later publishing a row that would
  satisfy the bare-ref read. So materializing a deleted or unowned ref fails to
  resolve; §5's network-before-disk ordering means nothing is written, and a
  different owner's payload is never silently substituted.

## 5. Materialization semantics

Given a resolved `library-url`, `blueprint`, and `profile`:

1. GET the catalog response (§4). No team certificate, no plugin, no signing —
   it is a public read.
2. **Validate structure before anything else:** every file path is normalized
   and unique (§2.1); `profile.yaml` is present and parseable; and its `id` /
   `version` equal the response `profile_ref` / `version`. Any failure rejects
   the payload; nothing is written.
3. **Verify integrity:** recompute the profile digest (§3) over the returned
   `files` and require it to equal `digest`. Also verify each file's
   `content_utf8` against its per-file `sha256`. Any mismatch fails closed;
   nothing is written. (This replaces the old get-profile-vs-shelf cross-check —
   integrity comes from the digest, not from a shelf round-trip.)
4. Materialize the profile files into the agent home for the requested runtime,
   staging in a temp dir and verifying paths stay within the home.
5. Write the pin (§6), recording the exact set of files written as the
   **managed set**.

Network-before-disk ordering means an auth/fetch/integrity failure writes
nothing.

## 6. The home pin

Materialization records, in `<home>/.aw/profile/ref.json`:

- `library_url` — the **client-resolved base URL** the home was materialized
  from (NEW: added so refresh re-pulls from the same provider). This is the base
  the client selected via arg → env → default and normalized (trailing slash
  stripped); it is **never** a value echoed back by the provider. Refresh uses
  this pinned base, so a provider response can never redirect a future refresh to
  another host.
- `source_blueprint_ref`, `source_blueprint_version` (provenance);
- `profile_ref`, `profile_version`, `profile_digest` (integrity + identity);
- the **managed set** — the exact list of files materialization wrote (NEW),
  so refresh can prune safely (§7).

The pin is provenance + the integrity anchor + the managed set. Homes update
**only** on explicit refresh — never automatically.

## 7. Refresh, and the shelf relationship

- **Public-blueprint refresh** re-pulls the profile from the **pinned**
  `library_url` + `source_blueprint_ref` (never a remote-chosen ref),
  recomputes the profile digest, and rewrites the home + pin. It is a **no-op**
  when `profile_digest` is unchanged and updates on change.
- **Refresh prunes only the managed set.** A file present in the old managed set
  (§6) but absent from the new payload is deleted; local/runtime state outside
  the managed set (the rest of `.aw/`, local edits) is preserved. Overwrite is
  not sync — without this, a skill removed upstream is orphaned in the home
  (this is the fix for the tracked bug `default-aaem`).
- **Shelf** reads (`get-shelf-profile?include=files`, cert-gated) return the
  **same materialize payload shape** (files + `profile_ref`/`version`/`digest`)
  plus shelf provenance (`source_*`, `tags`). So the materialize path is
  **identical** for public and shelf reads; only the fetch + auth differ. A
  plugin-free team can later adopt a public-materialized home onto its shelf
  from the pin (tracked in `aaeq.5`).

## 8. Conformance

`aaeq.2` provides shared conformance vectors (same pattern as the app-manifest
conformance suite) that **both** aw and library run: a well-formed catalog
response materializes to the expected file set + digest; digest mismatch fails
closed; missing `profile.yaml` fails; `profile.yaml` `id`/`version`
inconsistent with the response envelope fails; duplicate path rejected;
non-normalized path (absolute, `..`, `.`, `//`, trailing slash, backslash,
control char) rejected; path-escape rejected; a symlink at a visited entry
rejected (including a symlink whose name matches an excluded-directory name);
a symlink nested inside an excluded directory accepted (digest computed, symlink
ignored); non-UTF-8 file content rejected; U+2028/U+2029 content rejected; the pin is written with the client-resolved URL
+ managed set + all provenance/integrity fields; refresh no-ops at the same
digest, updates on change, and prunes an upstream-removed file while preserving
local/runtime state. A deliberate divergence on either side must red the vector
gate.

## Sign-off record

All three original open items are resolved (coordinator, 2026-07-02):

1. **Symlink rejection (§3 step 2)** — confirmed a real divergence (library
   `collect_files` follows symlinks; aw errors). The library-side fix is
   `default-aaeq.8`, with the aaeq.2 symlink-rejected vector as its acceptance.
2. **No blueprint digest in v1 (§4)** — confirmed and preferred: a blueprint
   digest changes whenever any sibling profile changes, so pinning it on a
   single-profile home would signal false drift on refresh. Profile digest is
   the integrity anchor; `blueprint_ref` + version is the provenance;
   `blueprint_digest` stays a clean additive field if ever wanted.
3. **U+2028/U+2029 prohibition (§3 step 5)** — confirmed as content policy;
   verified zero occurrences across the authored `aweb.team` files.

Hardened after sign-off with `aw-reviewer`'s pre-implementation review: strict
path normalization + unique paths (§2.1), a structural-validation step with
`profile.yaml` envelope-consistency (§5), the pin's `library_url` fixed as the
client-resolved base (§6), the managed set recorded for safe pruning (§6), and
refresh pruning of the managed set (§7, closes `default-aaem`).
