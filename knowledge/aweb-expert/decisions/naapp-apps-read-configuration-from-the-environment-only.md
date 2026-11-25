---
type: Decision
title: naapp apps read configuration from the environment only
description: naapp app settings never load a .env file, because apps that build at import took any .env in the starting directory as their configuration; dev targets pass a local .env explicitly, and a test leaking from a .env is fixed in the settings, never by passing _env_file=None in the test.
tags: [decision, configuration, settings, naapps]
timestamp: 2026-11-25
---

Folio and Library build their application when imported. With settings that
loaded `.env`, importing them read whatever `.env` sat in the directory the
process started in, so another checkout's or another tool's file silently
became the app's configuration; a planted `.env` broke `import folio.api`.
The deploy READMEs for Logs and Secrets already promised environment-only
configuration, so the settings were brought in line with that promise.

Decided with the naapps coordinator in November 2026 (source-reported; the
ruling thread is not readable by the harvester).

# Decision

- The shared naapp settings and every app's settings read the process
  environment only (`env_file=None`). Do not reintroduce `env_file=".env"`
  in any app, including a new one.
- Local development keeps its `.env`: the dev targets pass it explicitly to
  the server (`uv run --env-file .env`) when one exists.
- Each app keeps a test that a planted `.env` in the working directory leaves
  its settings unchanged.

# Rejected

- Keeping `.env` loading and passing `_env_file=None` in tests. That protects
  the tests, not the app that builds at import: production and any tool that
  imports the app still read a stray `.env`. A call site that passes
  `_env_file=None` is not precedent for fixing a leak that way.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/2026-11-25-settings-must-not-read-cwd-dotenv.md. Checked at
harvest on naapp main 1740e25: PRs #28 (Folio) and #38 (shared settings,
Library, Logs, Secrets) are merged, and every app settings class sets
`env_file=None`.
