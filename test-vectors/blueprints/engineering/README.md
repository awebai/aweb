# default-aaas.2.9 Engineering Blueprint Fixture

This fixture pins the launch blueprint contract used by `aw`, Library, and AC.
It is intentionally local-first and Library-optional.

## Locked shape

Source blueprint layout:

```text
source/
  blueprint.yaml
  README.md
  missions.yaml
  profiles/<id>/
    profile.yaml
    instructions.md
    skills/
    artifacts/
```

`blueprint.yaml` required fields: `id`, `name`, `version`, `summary`,
`description`, `profiles[]`. Optional fields include suggested counts,
`runtime_hints`, `expected_apps`, and `first_mission_examples`.

`profile.yaml` required fields: `id`, `name`, `version`, `mission`,
`accepted_work`, `instructions`, `runtime_assumptions`, `memory_policy`.
The `instructions` value is a relative path inside the profile directory.

`expected_apps` are setup/behavior hints only — not grants, scopes, approvals,
or authorization.

## Library-optional invariant

Library is not mandatory:

- `aw team create` must be able to create a team with empty profiles when
  Library is unreachable or unsubscribed.
- `aw agent add` must be able to add an agent with an empty profile/no binding.
- Blueprint import, Library refs, binding, and materialization are optional
  layers behind a later Library seam.

The inspect fixture therefore has `required_human_decisions: []` and uses
`optional_next_steps` for import/bind/materialize suggestions.

## Digest canonicalization

Blueprint and profile digests use the Folio-compatible canonical JSON primitive:

- JSON object keys sorted lexicographically at every level;
- compact separators `,` and `:`;
- literal UTF-8 (`ensure_ascii=false` / Go `SetEscapeHTML(false)`);
- SHA-256 over the canonical UTF-8 bytes, encoded as `sha256:<hex>`.

The blueprint import payload canonical input is:

```json
{"files":[{"content_utf8":"...","path":"...","sha256":"sha256:<file-bytes-hex>"}],"schema":"aweb.blueprint.import-payload.v1"}
```

Path bases are part of the conformance contract:

- `aweb.blueprint.import-payload.v1` uses **blueprint-relative** POSIX paths,
  relative to the blueprint root.
- `aweb.blueprint.profile-payload.v1` uses **profile-relative** POSIX paths,
  relative to `profiles/<profile_ref>/`.

Files are sorted by the payload's relative path base. VCS, dependency,
build/cache, and host-local runtime directories are excluded from the import
payload; `.aw`, identity material, keys, certs, tokens, secrets, generated
worktrees, symlinks, and host/path injection fail closed.

`expected/import-payload.canonical.json` is the exact canonical payload bytes.
`expected/import-payload.digest` is the blueprint digest.

## Expected Library import return

`expected/import-return.json` pins the shape returned by
`POST /v1/blueprints/import`:

```json
{
  "blueprint_ref": "aweb.engineering",
  "version": "0.1.0",
  "digest": "sha256:...",
  "profiles": [
    {"profile_ref": "coordinator", "version": "0.1.0", "digest": "sha256:..."}
  ]
}
```

`aw` records `profile_ref`, `profile_version`, `profile_digest`, and
`source_blueprint_ref` when/if a profile is materialized. Empty profiles/no
binding remain valid.

## Expected materialized layout

`expected/materialized-home/<profile-id>/` is the byte-exact composed agent-home
fixture shared by aw and Library. It supersedes the earlier verbatim
`instructions.md` materialized home. Each bound profile home contains:

```text
AGENTS.md
CLAUDE.md -> AGENTS.md
skills/...
.claude/skills/... -> skills/...
artifacts/...
.aw/profile/ref.json
.aw/profile/profile.yaml
.aw/profile/instructions.md
.aw/profile/skills/...
.aw/profile/artifacts/...
```

`AGENTS.md` is composed from the profile fields per
`docs/restructuring/agent-home-composition-contract.md`. `ref.json` contains
`profile_ref`, `profile_version`, `profile_digest`, `source_blueprint_ref`,
`source_blueprint_version`, and `source_blueprint_digest` for profiles
adopted from this blueprint.

`expected/materialized-home-created/developer/` pins the no-source-blueprint
provenance form for a shelf-created profile: the `AGENTS.md` provenance line is
`created`, and `.aw/profile/ref.json` intentionally omits
`source_blueprint_*` fields.

`expected/materialized-home-legacy/` preserves the previous .3.3 local CLI
output until `default-aaas.3.8` reworks the Go materializer to reproduce the
composed home byte-for-byte.

## Negative fixtures

`negatives/` contains packs that must fail validation:

- `.aw` runtime state;
- private keys;
- certificates;
- tokens;
- secret/identity content;
- generated worktrees;
- host/scheme path injection;
- symlinks.
