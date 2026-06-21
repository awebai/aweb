# Agent home composition (Library side)

This is the Library lane's mirror of the shared **Agent Home Composition
Contract** (SOT owned by the aw CLI lane, co-owned by Library). It describes what
`POST /v1/materialize` produces and why. The cross-lane byte-exact fixtures —
`tests/vectors/blueprints/engineering/expected/materialized-home/<id>/` and
`.../materialized-home-created/<id>/` — are the final arbiter; this prose
describes them, it does not override them. Both lanes reproduce the same fixture
byte-for-byte: Library in Python (`materialize_home`) and aw in Go (local
materialize), the same discipline as the digest vector.

## Why

A materialized agent home must be two things at once:

1. **Directly runnable** by a harness (Claude Code, codex, …) with no further
   assembly — the harness reads one canonical body file.
2. **Self-describing and evolvable** — it carries its full profile so the running
   agent can read what it is and propose a new version.

The prior `.2.9` behavior copied `instructions.md` verbatim and dropped
`mission`, `accepted_work`, `memory_policy`, `expected_apps`, and
`approval_required`. That home could neither run as an agent nor evolve. This
composition replaces it and supersedes the `.2.9` materialized-home.

## Source: the shelf profile

The home is materialized from the team's **private shelf** copy of the profile
(the bound profile), never from a public-blueprint ref directly. A shelf copy is
adopted from a public blueprint via `import-to-shelf` (recording `source_blueprint_*`
provenance) or created directly (no source blueprint). Blueprint profiles are public
snapshots; the home is always built from the shelf copy the team owns and evolves.

## Home layout

A bound (non-empty) profile materializes to:

```
<home>/
  AGENTS.md                      # composed body (canonical)
  CLAUDE.md -> AGENTS.md         # harness symlink
  skills/<skill-name>/SKILL.md   # installed, canonical skill files
  artifacts/<files>              # installed artifact files
  .claude/skills/<skill-name>/SKILL.md -> ../../../skills/<skill-name>/SKILL.md
  .aw/profile/                   # the full, evolvable profile
    ref.json                     # the pin (profile + source-blueprint digest/version)
    profile.yaml                 # the complete profile spec
    instructions.md              # editable source prose
    skills/<source skill files>
    artifacts/<source artifact files>
```

An empty (no bound profile) home is identity-only: no `AGENTS.md`, no
`.aw/profile/`, no skills/artifacts. Ids are creatable without a profile.

`home_files` entries returned by `POST /v1/materialize` are typed: a regular file
(`{path, kind: "file", content_utf8}`) or a symlink (`{path, kind: "symlink",
target}`).

## Field → destination

| Profile field | Destination |
|---|---|
| `mission` | `AGENTS.md` § Mission |
| `accepted_work` | `AGENTS.md` § Work you take on |
| `instructions` (prose) | `AGENTS.md` § Instructions (embedded verbatim) |
| `expected_apps` | `AGENTS.md` § Apps you use |
| `approval_required` | `AGENTS.md` § Actions requiring human approval |
| `memory_policy` | `AGENTS.md` § Memory and learning |
| `skills` | installed under `skills/` (+ per-harness symlinks); listed in § Skills |
| `artifacts` | installed under `artifacts/` |
| `runtime_assumptions` | selects the harness body file + symlink; not rendered into the body |
| `event_subscriptions` | registered with core for the wake loop; not rendered into the body |
| `id` / `version` + blueprint digests | `.aw/profile/ref.json` pin |
| full profile + source | `.aw/profile/` |

## AGENTS.md composition

`AGENTS.md` is **constructed** from the profile in this fixed section order, never
a verbatim copy of `instructions.md`:

```
# {name}

> Profile {id} v{version} · blueprint {blueprint_id} v{blueprint_version}

## Mission

{mission}

## Work you take on

{accepted_work as "- item" lines}

## Instructions

{instructions prose, embedded verbatim}

## Apps you use

{expected_apps as "- item" lines}

## Actions requiring human approval

{approval_required as "- item" lines}

## Memory and learning

Mode: {memory_policy.mode}
Proposal target: {memory_policy.proposal_target}

Your full profile is kept under .aw/profile/. To change how you work, propose a
new profile version from there; {memory_policy.proposal_target} reviews and mints
it.

## Skills

These skills are installed and discoverable by your harness:

{skills as "- {skill name}" lines}
```

Rendering rules (the fixtures are the arbiter):

1. UTF-8, LF line endings, exactly one trailing newline.
2. Exactly one blank line between a header and its body, and between sections.
3. Lists render as `- ` + item text, one per line, in profile order.
4. The instructions prose is embedded verbatim, its trailing newlines trimmed so a
   single blank line precedes the next section.
5. Any section whose source component is empty is **omitted entirely** — title and
   body. Only the `# {name}` header and the provenance line are always present.
6. The provenance line has two forms, both pinned by fixtures: adopted from a blueprint
   — `> Profile {id} v{version} · blueprint {blueprint_id} v{blueprint_version}`; created directly
   on the shelf — `> Profile {id} v{version} · created`.
7. The Memory boilerplate names the profile's own `proposal_target` (e.g.
   `library`), not a hardcoded value.

## Harness body file + symlink

`AGENTS.md` is the canonical body for every harness; the harness entry file is a
symlink to it, selected by `runtime_assumptions`. `claude-code` (and the default):
`CLAUDE.md -> AGENTS.md`. `codex`: `AGENTS.md` is native, no extra symlink. The
body is never duplicated, so evolution touches one file.

## Skills

Skill content is installed once, canonically, under `skills/<skill-name>/`. For
each harness's standard skill location, materialize creates that location and
populates it with symlinks back to `skills/` (e.g. `.claude/skills/<name>/SKILL.md
-> ../../../skills/<name>/SKILL.md`). Content lives exactly once; every harness
discovers it without duplication. The body's § Skills lists installed skills by
name.

## The evolvable profile (`.aw/profile/`)

Materialize writes the **full** profile into `.aw/profile/`: `ref.json` (the pin),
`profile.yaml`, `instructions.md`, and the source `skills/`/`artifacts/`. This is
the substrate for evolution: the agent reads its current profile here and proposes
a new version to its `memory_policy.proposal_target` (e.g. Library), which reviews
and mints it — the proposal/minting flow. `AGENTS.md` and the installed
`skills/`/`artifacts/` are **derived** from this source.

`ref.json` records `source_blueprint_*` as **provenance** (where the shelf copy
was adopted from) for a blueprint copy, and omits it for a profile created fresh on the
shelf (the provenance line then reads `· created`). Provenance is what
`update-from-source` uses to pull a newer blueprint version's improvements into only the
parts the team has not evolved (per-part merge), without clobbering local learning.
