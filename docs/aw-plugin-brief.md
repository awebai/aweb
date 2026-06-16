# aw plugin mechanism — design brief for the aweb team

Status: **SUPERSEDED (2026-06-16)** by the frozen app-manifest contract
(`aweb/docs/restructuring/app-manifest-schema.md`). The aweb team chose a
**manifest-driven generic dispatcher** — one declaration drives both the hosted
gateway's MCP tools and `aw <app>` verbs over `aw id request --team-auth`, with
no per-app binary. That dissolves this brief's core problem: a private repo
can't ship a distributable binary, but it can publish a static manifest. folio's
verb surface and the end-to-end proof are tracked in `default-aaai.3`. This brief
is kept only as the record of the external-binary path that was considered and
rejected; do not implement it.

Status (original): proposal (2026-06-15). Author: folio team (coordinator).
Audience: the aweb team that owns the `aw` Go CLI.

## Goal

Let agent-native apps ("anapps") like folio add **aw-native verbs** (`aw folio
create ...`) without compiling every app into core `aw`. This is the CLI half
of the anapps convention already adopted for skills: each anapp publishes its
`/llms.txt` + `/skills/`, the aweb.ai hub indexes them — and now each anapp can
also ship CLI verbs the same decoupled way.

Today `aw` is a single cobra binary; every command group is compiled in via
`rootCmd.AddCommand(...)`. There is no plugin/extension mechanism. folio's
verbs currently ship as a Python console script inside the **private** folio
repo, which is undistributable — hence this brief.

## Recommended mechanism: external-binary dispatch (the kubectl / gh model)

On an unknown subcommand `aw <name>`, `aw` resolves an executable `aw-<name>`
(from `~/.aw/plugins/` and `PATH`) and `exec`s it, forwarding the remaining
args. The plugin is a separate binary in any language; no shared memory, no ABI
coupling.

- **Decoupled:** core `aw` never imports folio; it just execs `aw-folio`.
- **Distributable from a private app:** the plugin ships as its own release
  artifact (binary), so a private repo is no blocker — publish the `aw-folio`
  binary as a (possibly auth'd) release download.
- **Proven with cobra:** `kubectl` is cobra-based and does exactly this, so it
  fits `aw`'s stack. Intercept the "unknown command" path, look up the plugin,
  exec; fall back to the normal error if none found.

### Alternatives considered (and why not)

- **Go's native `plugin` package (`.so`)** — ABI-locked to identical
  toolchain/deps, Linux/macOS only, can't unload. Avoid.
- **HashiCorp `go-plugin` (gRPC subprocess)** — great when the host calls *into*
  the plugin repeatedly with typed data (Terraform/Vault). Overkill for "add a
  few verbs."
- **Built-in command groups in core aw** — couples `aw` to every anapp; doesn't
  scale to an open ecosystem.

## Context contract (aw → plugin)

Pass context via environment, never secrets in argv:

- `AW_DID` / active identity, `AW_TEAM` (active team), `AW_SERVER` (aweb server),
  `AW_HOME`/profile.
- `AW_HELPER` — path to the `aw` binary so the plugin can re-invoke
  `aw id request --team-auth ...` for authenticated calls (folio's verbs are
  already just sugar over `aw id request`). This keeps auth in `aw`; the plugin
  never handles raw team keys.

## Plugin management UX (gh-style)

- `aw plugin list` — installed plugins.
- `aw plugin install <source>` — fetch a release binary into `~/.aw/plugins/`.
- `aw plugin remove <name>`.
- `aw plugin search` — optional, queries the aweb.ai hub.

## Hub integration (anapps convention)

The aweb.ai hub indexes anapp plugins next to their `/skills/` + `/llms.txt`, so
discovery for skills and verbs is one surface. An anapp's home page advertises:
its API, its skills, and its `aw <name>` plugin.

## Security / trust model

- Only exec plugins from trusted locations (`~/.aw/plugins/`, `PATH`); warn on
  first run of a newly installed plugin.
- Never pass team secrets in argv; use env + the `aw id request` helper so auth
  stays in `aw`.
- Plugins run with the user's privileges — document this. Consider signed
  release artifacts / a manifest later.

## folio as the reference plugin

`aw-folio` implements create / version / upload / show / theme / present by
calling the folio API with the aw-provided identity. It is the first proof of
the pattern and replaces the removed Python CLI. Distributed as a release
binary independent of the private folio repo.

## Phasing

1. **aweb team:** add dispatch + the context env contract + `aw plugin`
   management to the `aw` CLI.
2. **folio team:** ship `aw-folio` as the reference plugin.
3. **hub:** index anapp plugins.

Until step 2 lands, agents use the generic `aw id request --team-auth` plus
folio's `/skills/` (including `create-from-template`) and `/llms.txt`.

## Open questions

- Plugin auth: re-shell `aw id request` (simplest) vs a token-passing helper
  API for performance?
- Windows support (`aw-<name>.exe` naming; PATH dispatch still works).
- Version/compatibility signalling between `aw` and a plugin.
