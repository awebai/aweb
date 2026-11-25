---
type: Lesson
title: A uv git pin brings its own tool.uv.sources
description: Pinning an aweb subproject by git URL makes uv honour that subproject's own path sources inside the git repository, which conflicts with a local copy of the same package; pin the published wheel instead, and do not use override-dependencies, which silently drops extras.
tags: [lesson, uv, dependencies, packaging, repository-split]
timestamp: 2026-11-25
---

A git dependency in uv is resolved with the dependency's own `tool.uv.sources`.
When the apps repository pinned the aweb server by git URL
(`git+https://github.com/awebai/aweb@d8ee9ed#subdirectory=...`), the server's
`aweb-naapp = {path = "../naapp-lib"}` source was resolved inside the aweb git
repository and became a git URL. The apps repository also provides
`aweb-naapp` locally, so `uv lock` failed with "conflicting URLs for package
aweb-naapp". Observed with uv 0.13.9.

# Rejected

- `[tool.uv] override-dependencies = ["aweb-naapp"]`. It replaces every
  requirement on the package, extras included, and silently removed the
  runtime extra's dependencies (webauthn and others) from a lock. For the root
  project itself uv refuses it outright ("workspace member ... missing an entry
  in tool.uv.sources").

# How to apply

- Git-pin an aweb subproject only when its own `tool.uv.sources` point at
  nothing you also provide locally. awid has no `tool.uv.sources`, so its git
  pin was safe.
- Otherwise pin the published artifact: a wheel carries no sources. The apps
  repository takes the server from PyPI (`aweb` 1.27.53); the source reports
  that aweb's server tree at d8ee9ed was byte-identical to the released tag
  server-v1.27.53 apart from `server/uv.lock`.
- After any override or pin change, diff the lock for packages that
  disappeared, not only for the one you meant to change.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/uv-git-pin-carries-its-sources.md. The uv behaviour is as observed with
uv 0.13.9 and may change in later releases.
