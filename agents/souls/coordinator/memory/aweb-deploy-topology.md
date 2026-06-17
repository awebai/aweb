---
name: aweb-deploy-topology
description: app.aweb.ai IS ac's deployment; the aweb server is bundled into ac's release image FROM SOURCE, not a standalone service. aweb changes (e.g. m3.x) ship via an ac v* release — there is no separate aweb deploy pipeline.
metadata:
  type: project
---

Verified 2026-06-17 — after I **and** aw-coordinator misdiagnosed it as "the
aweb server is the one hosted service missing its own release pipeline" and I
nearly had a developer build + route a bogus `aweb-server-release.yml`. Juan
caught it ("is the current app.aweb.ai that we deploy with ac not enough?").

**How `app.aweb.ai` actually deploys:**
- `app.aweb.ai/api` = **ac** (aweb-cloud) serving the aweb OSS server, which ac
  **mounts in-process** (`ac/backend/src/aweb_cloud/main.py`:
  `from aweb.api import create_app` → mounted under `/api`).
- ac depends on the aweb **package** for dev (`ac/backend/pyproject.toml`:
  `aweb>=1.26.18`), but the **hosted release bundles aweb FROM SOURCE**:
  `ac/Dockerfile.release` does `uv pip install --no-deps /src/aweb/server`
  (+ `/src/aweb/awid`), via `build-contexts: aweb_server=./aweb-source/server`,
  where ac CI (`aweb-cloud-ci-cd.yml`, on a `v*` tag) checks out `awebai/aweb`.
- `ac/scripts/check_release_model.py` ties the shipped aweb **source** version
  to ac's `uv.lock` aweb version (determinism guard).
- aweb's own `server-release.yml` only **publishes the package to PyPI** — a dev
  baseline, **not** a hosted deploy. aweb has NO standalone hosted service and
  NO image-release workflow, and does not need one.

**So to deploy an aweb change (m3.2, etc.) to `app.aweb.ai`:** ac bumps its
aweb pin + cuts a `v*` release; ac CI rebuilds the combined image from aweb
source. **Deploy owner = ac (ac-coordinator), not a separate aweb/ops pipeline.**

**How to apply:** don't infer a component's standalone-ness or a "missing
pipeline" from CI-workflow presence alone — check the actual integration
(here, ac embeds + ships the aweb server from source across the repo boundary).
Verify deploy/coupling facts in code before escalating or building. See
[[correctness-over-momentum]].
