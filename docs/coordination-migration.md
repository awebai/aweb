# Coordination Migration

This note covers the invariants-to-project-instructions transition and the
expected rollout order for self-hosted operators and client maintainers.

## What Changed

- Shared coordination guidance is now stored as a first-class
  `project_instructions` resource.
- Active project roles remain the source for role playbooks and adapters.
- `roles show` is role-only. Shared guidance is no longer emitted there.
- Local `AGENTS.md` / `CLAUDE.md` injection is derived from the active project
  instructions, not from a second hardcoded CLI template.

## Compatibility

- Older projects that still have legacy `bundle.invariants` are migrated lazily:
  the server backfills active `project_instructions` from those invariants on
  first instructions read.
- Older clients may continue to describe `roles show` or `--inject-docs` using
  the pre-split wording until they are upgraded.
- The server-side history response uses
  `project_instructions_versions`. Clients that need to tolerate the short-lived
  singular field from pre-release server builds should do so explicitly.

## Recommended Rollout

1. Upgrade the server so `project_instructions` and the new defaults exist.
2. Read `/v1/instructions/active` or use `aw instructions show` once in each
   older project to trigger lazy backfill when needed.
3. Upgrade CLI clients so roles, instructions, and inject-docs all use the same
   split model.
4. Refresh injected local docs with `aw init --inject-docs` or the equivalent
   bootstrap flow after the CLI upgrade.

## Cross-Surface Expectations

- REST:
  - `/v1/roles/active` is roles-only.
  - `/v1/instructions/*` is the canonical shared-guidance API.
- MCP:
  - `roles_show` is roles-only.
  - `instructions_show` and `instructions_history` expose shared instructions.
- CLI:
  - `aw roles show` reports role guidance only.
  - `aw instructions ...` manages shared instructions.
  - `--inject-docs` renders the active project instructions into local files.

## Hosted Follow-On

The hosted/dashboard editing experience for project instructions is tracked
separately in the `aweb-cloud` task slice (`aweb-aabn.5`). This note only
covers the OSS/server/CLI rollout and compatibility story.
