# Agent Home Composition Contract (SOT)

Status: draft v1 (2026-06-19), owned by the aw CLI lane (aw-coordinator),
co-owned with the Library lane (coordinator) because the Library docs must
describe the same composition. Pairs with the blueprint digest/import/
materialize contract and the team-builder ↔ Library contract.

## 0. Why this exists

A materialized agent home must be two things at once:

1. **Directly runnable** by an agent harness (Claude Code, codex, pi, …) with
   no further assembly — the harness reads one canonical body file.
2. **Self-describing and evolvable** — it carries its own full profile so the
   running agent can read what it is and propose a new version.

The prior materialize behavior copied `instructions.md` verbatim and dropped
`mission`, `accepted_work`, `memory_policy`, `expected_apps`, and
`approval_required`. That home would not run as an agent and could not evolve.
This contract replaces that behavior. It is byte-exact: the engineering
fixtures (§10) are the final arbiter, the same discipline as the digest vectors.

## 1. Input — the profile

The profile (see the profile schema) provides:

- `id`, `name`, `version` — identity
- `mission` — what kind of coworker this is / what it is for
- `accepted_work` — list of work it takes on
- `instructions` — pointer to the prose behavioral file (e.g. `instructions.md`)
- `runtime_assumptions` — list; selects the harness and launch, NOT body content
- `memory_policy` — `{ mode, proposal_target }`
- `expected_apps` — list of apps it expects to use
- `event_subscriptions` — list of `{ app, event }`; registered with core, NOT body
- `approval_required` — list of actions needing human sign-off
- `skills` — list of `{ path, kind }`; installed + discoverable (§6)
- `artifacts` — list of `{ path, kind }`; installed alongside the home

## 2. Home layout (exact)

A bound (non-empty) profile materializes to:

```
<home>/
  AGENTS.md                      # composed body (canonical, §4)
  CLAUDE.md -> AGENTS.md         # harness symlink (§5)
  skills/                        # installed, discoverable by every harness (§6)
    <skill-name>/SKILL.md
  artifacts/                     # installed
    <artifact files>
  .mcp.json                      # aweb channel MCP server config (§7)
  .claude/settings.json          # aw notify PostToolUse hook (§7)
  .aw/
    profile/                     # the evolvable profile (§8)
      ref.json                   # the pin (digest + version)
      profile.yaml               # the full profile spec
      instructions.md            # editable source prose
      skills/   <source skill files>
      artifacts/ <source artifact files>
```

An empty (no profile bound) home is identity-only: no `AGENTS.md`, no
`.aw/profile/`, no skills/artifacts. (Juan invariant — ids creatable without a
profile.) See §9.

## 3. Field → destination (the whole profile, accounted for)

| Profile field | Destination |
|---|---|
| `mission` | `AGENTS.md` §Mission |
| `accepted_work` | `AGENTS.md` §Work you take on |
| `instructions` (prose) | `AGENTS.md` §Instructions (embedded verbatim) |
| `expected_apps` | `AGENTS.md` §Apps you use |
| `approval_required` | `AGENTS.md` §Actions requiring human approval |
| `memory_policy` | `AGENTS.md` §Memory and learning |
| `skills` | installed under `skills/` + discoverable (§6); listed in `AGENTS.md` §Skills |
| `artifacts` | installed under `artifacts/` |
| `runtime_assumptions` | selects the harness body file + symlink (§5) and launch; not rendered into the body |
| `event_subscriptions` | registered with core for the wake loop; not rendered into the body |
| `id` / `version` + blueprint digests | `.aw/profile/ref.json` pin |
| full profile + source | `.aw/profile/` (§8) |

## 4. `AGENTS.md` composition (exact)

`AGENTS.md` is **constructed** from the profile in the fixed section order
below. It is never a verbatim copy of `instructions.md`. The source profile is
the team's **private shelf** copy (the bound profile), not a public blueprint profile
— blueprint profiles are public snapshots; the home is built from the shelf copy.

Template (sections in this order):

```
# {name}

> Profile {id} v{version} · blueprint {blueprint_id} v{blueprint_version}

## Mission

{mission}

## Work you take on

{accepted_work as a "- item" list, one per line}

## Instructions

{contents of the instructions prose file, embedded verbatim}

## Apps you use

{expected_apps as a "- item" list}

## Actions requiring human approval

{approval_required as a "- item" list}

## Memory and learning

Mode: {memory_policy.mode}
Proposal target: {memory_policy.proposal_target}

Your full profile is kept under .aw/profile/. To change how you work, propose a
new profile version from there; {memory_policy.proposal_target} reviews and mints
it.

## Skills

These skills are installed and discoverable by your harness:

{skills as a "- {skill name}" list}
```

Rendering rules (for byte-exactness; fixtures in §10 are the arbiter):

1. UTF-8, LF line endings, exactly one trailing newline at end of file.
2. Exactly one blank line between a header and its body, and between sections.
3. Lists render as `- ` + the item text, one per line, in profile order.
4. The instructions prose is embedded verbatim; its trailing whitespace is
   normalized to end with a single LF, then one blank line precedes the next
   section.
5. Any section whose source component is empty (empty string or empty list) is
   **omitted entirely** — section title and body — no empty headers. This applies
   uniformly to every composed section (Mission, Work you take on, Instructions,
   Apps you use, Actions requiring human approval, Memory and learning, Skills).
   Only the header line (`# {name}`) and the provenance line are always present.
6. The provenance line is always present, in one of two forms. Adopted from a
   source blueprint: `> Profile {id} v{version} · blueprint {blueprint_id} v{blueprint_version}`.
   Created directly on the shelf (no source blueprint — a created or forked variant):
   `> Profile {id} v{version} · created`. The fixtures pin both forms.

## 5. Harness body file + symlink

`AGENTS.md` is the canonical body for every harness. The harness-specific entry
file is a **symlink** to it, selected by `runtime_assumptions`:

- `claude-code` (and the default when no harness is declared):
  `CLAUDE.md -> AGENTS.md`.
- `codex`: `AGENTS.md` is already the native file; no extra symlink.
- other harnesses: same pattern — canonical `AGENTS.md` plus the harness's
  expected entry file symlinked to it. Each harness mapping is pinned as it is
  added; `claude-code` and default are normative now.

Never duplicate the body; always symlink so evolution touches one file.

## 6. Skills — installed where harnesses expect them

Skill content is installed once, canonically, under `<home>/skills/<skill-name>/`
— this directory holds the real files. Harnesses expect skills in specific
standard locations; for each such standard location, materialize **creates that
location and populates it with symlinks to the files under `skills/`**. So the
content lives exactly once (in `skills/`) and is discoverable by every harness
without duplication. (E.g. a harness that discovers skills under its own
directory gets that directory created with symlinks into `skills/`.) The set of
standard locations is pinned per harness (claude-code first); the invariant is
that an installed skill is discoverable by whatever harness runs the home, with
`skills/` as the single source of the files. The body's §Skills lists the
installed skills by name so the agent knows they exist.

## 7. Team coordination block + wake-loop wiring

A Library-bound `aw team create --profile ...` or `aw team add NAME@BLUEPRINT/PROFILE`
materialization also converges the home with the normal `aw init` agent setup:

- append/refresh the team's active aweb coordination instructions in `AGENTS.md`
  between `<!-- AWEB:START -->` and `<!-- AWEB:END -->` markers;
- create/update `.mcp.json` with the `aweb` channel MCP server;
- create/update `.claude/settings.json` with the `aw notify` `PostToolUse` hook.

The coordination block is not duplicated in public profiles or blueprints. It is
loaded from the active team instructions document at materialization time, so
team-local coordination policy remains a single source of truth. Empty-profile
identity-only homes remain empty (§9) until a profile is bound.

## 8. The evolvable profile (`.aw/profile/`)

Materialize writes the **full** profile into `.aw/profile/`, not just the pin:

- `ref.json` — the pin (profile digest + version, source blueprint digest + version).
- `profile.yaml` — the complete profile spec.
- `instructions.md`, `skills/`, `artifacts/` — the editable source the agent
  evolves.

This is the substrate for the evolution loop: the agent reads its current
profile here and proposes a new version (`memory_policy.proposal_target`, e.g.
Library, reviews and mints it — the proposal/version-minting flow). `AGENTS.md`
and the installed `skills/`,`artifacts/` are **derived** from this source; the
source under `.aw/profile/` is canonical for evolution.

### Relationship to the team shelf

The materialized `.aw/profile/` is the local manifestation of the team's
**private shelf** profile — the copy the team owns and evolves. It is never a
bare public-blueprint ref. In `ref.json`, `source_blueprint_*` is **provenance**
(where the shelf copy was adopted from), which enables `update-from-source`:
pulling a newer blueprint version's improvements into only the parts the team has not
evolved (per-part merge), without clobbering local learning. A shelf profile may
also be created directly (no source blueprint), in which case the source provenance is
empty. Adoption from a public blueprint is `import-to-shelf` (a copy); the home then
materializes from that shelf copy, not from the public blueprint ref.

## 9. Empty profile

No bound profile → identity-only home: the `.aw` identity/team material, no
`AGENTS.md`, no `.aw/profile/`, no skills/artifacts, no Library registration.
Binding a profile later runs the full composition above. (Juan invariant.)

## 10. Conformance

Byte-exact `expected/materialized-home/<id>/` fixtures for the engineering blueprint
(`coordinator`, `developer`, `reviewer`): the composed `AGENTS.md`, the
`CLAUDE.md` symlink, the installed `skills/` and `artifacts/`, and the full
`.aw/profile/`.

These fixtures are the **shared cross-lane byte-parity vector**: both Library
(Python, `POST /v1/materialize`) and aw (Go, local materialize) reproduce them
byte-for-byte — the same discipline as the digest vector, one shared vector. The
aw lane lands the updated materialized-home fixture **first**; both sides then
reproduce it. This fixture **supersedes** the prior `.2.9` materialized-home
(verbatim `instructions.md` + `ref.json` only). These fixtures, not this prose,
are the final arbiter of the exact composition.

## 11. Tasks

- `default-aaas.3.7` — this contract + the conformance fixtures.
- `default-aaas.3.8` — rework materialize to emit this layout; supersedes the
  home output of `default-aaas.3.3`.
- `default-aaas.3.4/.3.5/.3.6` depend on `.3.8` (they need a runnable home).
