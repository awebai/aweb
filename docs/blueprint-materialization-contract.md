---
title: "Blueprint materialization contract (import-payload v1)"
kicker: "Contract SOT — DRAFT for sign-off"
description: "The one contract that aw and library both implement: profile/blueprint payload shape, the canonical digest, the public catalog response, materialization semantics, and the home pin. Materialization is a public read; the shelf is a separate opt-in app."
weight: 27
---

# Blueprint materialization contract (import-payload v1)

Status: **DRAFT — pending sign-off** from the library service owner and
`atext.aweb.ai/coordinator` (seed-catalog owner). Tracked as `default-aaeq.1`.
Do not build `aaeq.3` against this until signed off.

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

- `path` is POSIX-relative to the payload root (profile root for
  profile-payload, blueprint root for import-payload). No absolute paths, no
  `..`, no scheme/host.
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
2. **NEW — symlinks:** a symlink anywhere in the payload is an ERROR; the
   payload is rejected. (Today aw errors on symlinks; the library follows them.
   The library MUST be changed to reject them so the two sides can never
   disagree on bytes.)
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
  "blueprint_version": "0.1.3",
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

## 5. Materialization semantics

Given a resolved `library-url`, `blueprint`, and `profile`:

1. GET the catalog response (§4). No team certificate, no plugin, no signing —
   it is a public read.
2. **Verify integrity before writing anything:** recompute the profile digest
   (§3) over the returned `files` and require it to equal `digest`. Also verify
   each file's `content_utf8` against its per-file `sha256`. Any mismatch fails
   closed; nothing is written. (This replaces the old get-profile-vs-shelf
   cross-check — integrity comes from the digest, not from a shelf round-trip.)
3. Materialize the profile files into the agent home for the requested runtime,
   staging in a temp dir and verifying paths stay within the home.
4. Write the pin (§6).

Network-before-disk ordering means an auth/fetch/integrity failure writes
nothing.

## 6. The home pin

Materialization records, in `<home>/.aw/profile/ref.json`:

- `library_url` — the **resolved** source URL the home was materialized from
  (NEW: added so refresh re-pulls from the same provider);
- `source_blueprint_ref`, `source_blueprint_version` (provenance);
- `profile_ref`, `profile_version`, `profile_digest` (integrity + identity).

The pin is provenance + the integrity anchor. Homes update **only** on explicit
refresh — never automatically.

## 7. Refresh, and the shelf relationship

- **Public-blueprint refresh** re-pulls the profile from the **pinned**
  `library_url` + `source_blueprint_ref` (never a remote-chosen ref),
  recomputes the profile digest, and rewrites the home + pin. It is a **no-op**
  when `profile_digest` is unchanged and updates on change.
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
closed; missing `profile.yaml` fails; path-escape rejected; symlink rejected;
U+2028/U+2029 content rejected; the pin is written with the resolved URL + all
provenance/integrity fields; refresh no-ops at the same digest and updates on
change. A deliberate divergence on either side must red the vector gate.

## Open items for sign-off

1. **Library change required (§3 step 2):** reject symlinks in payloads (today
   it follows them). Small, but it is a real cross-impl divergence.
2. **Confirm §4 decision:** no blueprint digest on the public response in v1
   (profile digest is the integrity anchor). Library owner + coordinator to
   confirm, or ask for the optional `blueprint_digest` additive field now.
3. **Confirm the U+2028/U+2029 prohibition (§3 step 5)** is acceptable content
   policy for seed profiles (it is, for text profiles — flagging for
   completeness).
