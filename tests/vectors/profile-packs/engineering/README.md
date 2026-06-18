# default-aaas.2.9 Engineering Profile-Pack Fixture

This fixture pins the launch profile-pack contract used by `aw`, Library, and AC.
It is intentionally local-first and Library-optional.

## Locked shape

Source pack layout:

```text
source/
  pack.yaml
  README.md
  missions.yaml
  profiles/<id>/
    profile.yaml
    instructions.md
    skills/
    artifacts/
```

`pack.yaml` required fields: `id`, `name`, `version`, `summary`,
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
- Profile-pack import, Library refs, binding, and materialization are optional
  layers behind a later Library seam.

The inspect fixture therefore has `required_human_decisions: []` and uses
`optional_next_steps` for import/bind/materialize suggestions.

## Digest canonicalization

Pack and profile digests use the Folio-compatible canonical JSON primitive:

- JSON object keys sorted lexicographically at every level;
- compact separators `,` and `:`;
- literal UTF-8 (`ensure_ascii=false` / Go `SetEscapeHTML(false)`);
- SHA-256 over the canonical UTF-8 bytes, encoded as `sha256:<hex>`.

The pack import payload canonical input is:

```json
{"files":[{"content_utf8":"...","path":"...","sha256":"sha256:<file-bytes-hex>"}],"schema":"aweb.profile-pack.import-payload.v1"}
```

Path bases are part of the conformance contract:

- `aweb.profile-pack.import-payload.v1` uses **pack-relative** POSIX paths,
  relative to the profile-pack root.
- `aweb.profile-pack.profile-payload.v1` uses **profile-relative** POSIX paths,
  relative to `profiles/<profile_ref>/`.

Files are sorted by the payload's relative path base. VCS, dependency,
build/cache, and host-local runtime directories are excluded from the import
payload; `.aw`, identity material, keys, certs, tokens, secrets, generated
worktrees, symlinks, and host/path injection fail closed.

`expected/import-payload.canonical.json` is the exact canonical payload bytes.
`expected/import-payload.digest` is the pack digest.

## Expected Library import return

`expected/import-return.json` pins the shape returned by
`POST /v1/profile-packs/import`:

```json
{
  "pack_ref": "aweb.engineering-pack",
  "version": "0.1.0",
  "digest": "sha256:...",
  "profiles": [
    {"profile_ref": "coordinator", "version": "0.1.0", "digest": "sha256:..."}
  ]
}
```

`aw` records `profile_ref`, `profile_version`, `profile_digest`, and
`source_profile_pack_ref` when/if a profile is materialized. Empty profiles/no
binding remain valid.

## Expected materialized layout

`expected/materialized-home/<profile-id>/` defines the local files that a later
materialize step writes into an agent home:

```text
.aw/profile/ref.json
instructions.md
skills/...
artifacts/...
```

`ref.json` contains `profile_ref`, `profile_version`, `profile_digest`,
`source_profile_pack_ref`, `source_profile_pack_version`, and
`source_profile_pack_digest`.

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
