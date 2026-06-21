# aw Command Surface (SOT)

Status: v1 (2026-06-19), owned by the aw CLI lane (aw-coordinator). Pairs with
the agent-home composition contract, the import-to-shelf pin, and the
shelf-centric Library model. This is the decided shape of the `aw` command
surface for the profile/team/Library work (default-aaas.3 line).

## 0. Organizing principle

**Work from your private shelf; visit the catalog to adopt or publish. What you
adopt is a private copy you own and evolve.**

The surface splits cleanly into two halves:

- **aw-local** — hand-coded primitives that act on identity, team membership,
  and the agent home on disk.
- **`aw library`** — the Library **plugin**: every interaction with Library,
  auto-built from the Library manifest. Not hand-coded verbs.

## 1. aw-local primitives (hand-coded)

These act locally (identity, certs, files); none of them is Library-specific.

- **`aw id` — mint/manage an identity anywhere.** `aw id create` instantiates an
  identity with no team required. The id is the base primitive; team membership
  is layered on top. "Instantiate an id anywhere" is first-class and must not be
  folded away.
- **invite / accept-invite — the cross-machine join flow.** `aw team invite`
  generates a token; the joiner runs `aw team join` / `aw id team accept-invite`.
  First-class, kept.
- **`aw team create <name> [--profile <ref>[:n]]…`** — create a team. Reuses
  `aw init`'s full branching, keyed on **identity existence and namespace
  control, not registry location**: no identity → `aw init`'s bundle (hosted
  onboarding by default, local-implicit on a localhost stack); existing
  self-custodial identity → mint a new team under its namespace, signed, no
  re-signup; hosted-managed identity → the hosted create-team path. There is no
  "requires a local awid registry" gate. See
  `team-create-and-membership-model.md` for the full contract. No `--profile` →
  an empty-profile team (hard invariant). `--profile` composes a Library adopt +
  a local materialize (§3). `--byot`/`--namespace` is the explicit
  self-custodial create for a domain you control.
- **`aw team add <name>[@<ref>]…`** — product-grade add of agent(s) to an
  existing team, on the `agents/instances/<name>/` layout (reusing the proven
  add-agent internals: unique-alias naming, identity + team-cert,
  `--local/--global`, `--layout-only`). API-key-prefixed, this is the
  dashboard/wizard self-host incantation. `@<ref>` → adopt + bind + materialize;
  bare name → an empty agent (no shelf, no Library — hard invariant).
- **materialize a runnable home** — the agent-home composition (composed
  `AGENTS.md` + `CLAUDE.md`/harness symlink + harness-discoverable skills + the
  full evolvable `.aw/profile/`). A local disk operation; see the agent-home
  composition contract. This is what `--profile`/`@ref` triggers locally.

**Retires:** the obsolete bootstrap-era `aw agents` surface (`bootstrap`,
`plan`, `provision`, `add`, `add-worktree`, `remove` on the `agents/home`
layout) retires once `aw team add` covers product-grade provisioning. The id and
invite/accept-invite primitives live on independently — they are NOT part of
what retires.

## 2. `aw library` — the Library plugin (manifest-driven)

**All** Library interaction goes through `aw library <verb>`, and `aw library` is
**auto-built from the Library manifest** — the same mechanism that gives
`aw folio`. There is nothing new to build in the CLI for this.

How it works (already shipped):
- The Library app publishes a manifest (`manifest_version: 1`, see
  `internal/appmanifest`): `tools[]` (each a verb with `method`/`path`/`params`/
  `body`), `skills`, and `event_emitters`.
- `aw plugin install <library-manifest-url>` installs it; the app becomes the
  top-level `aw library` command (`aw plugin reserved-names` reserves the id).
- Each manifest tool becomes `aw library <verb> --param …`;
  `appmanifest.Interpret` builds the signed request. `aw plugin update`
  re-fetches the manifest, so the surface tracks it.

The Library operations that thus appear under `aw library`: browse the public
catalog, **adopt** (= import-to-shelf), list the shelf, update-from-source,
publish, propose-evolution — whatever the Library manifest declares. Adding a
Library operation is a manifest change, not a CLI change.

`aw profile` and `aw catalog` as bespoke command groups are **rejected** — they
duplicate what the Library manifest already describes. The shelf and catalog are
Library concepts; their CLI surface is `aw library`.

## 3. The composition seam

`aw team create --profile X` and `aw team add name@X` **compose** the two halves:
1. `aw library` makes the **adopt / import-to-shelf** call (a private shelf
   copy);
2. aw-local **materializes** the runnable home from that shelf copy.

API call (plugin) vs disk (aw-local). An empty profile does neither.

## 4. Cross-lane requirement — manifest-v1 fit

For `aw library` to auto-build, the Library manifest must express each Library
operation as a `manifest_version: 1` tool. Fit-check items (coordinator owns the
manifest, task default-aaas.14.4):

- manifest v1 has no number/float body fields — Library bodies must be
  strings/refs/objects.
- team-cert auth must be expressible (the manifest tools are signed with the
  team cert, as today).
- the finalized `import-to-shelf` (`POST /v1/shelf/import`, request
  `{source_blueprint_ref, source_blueprint_version?, profile_ref, tags?}`)
  maps to one tool.

Any operation that does not fit v1 is a manifest-spec gap to close (coordinator +
aw), not a reason to hand-code a CLI verb.

## 5. What this supersedes / decides

- The earlier three "verb decisions" resolve: `aw team add` is the add-member
  verb and is what the dashboard emits; `aw team create` drops
  `--hosted/--self-host`.
- `aw profile` + `aw catalog` are dropped in favor of `aw library`.
- `aw agents` (obsolete) retires; `aw id` + invite/accept-invite stay.

## 6. Tasks

- `default-aaas.3.4` — `aw team create` (retargeted to this SOT).
- `default-aaas.3.5` — `aw team add` (retargeted; preserves id + invite/accept).
- `default-aaas.3.6` — agent/team start + status (launch from
  `runtime_assumptions`, reads the materialized home).
- `default-aaas.3.7` / `.3.8` — agent-home composition (in flight).
- `default-aaas.3.9` — `aw library` plugin: validate manifest-v1 fit + that the
  Library manifest renders into `aw library` (mostly existing plugin mechanism).
