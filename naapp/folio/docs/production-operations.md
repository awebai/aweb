# Folio production operations

Production actions (deploys, service setting changes, rollbacks) are taken by
the hosted operator on an explicit go. This document states what the build
needs; it grants no authority to act.

## Build

Folio depends on the awid and naapp-lib of the aweb checkout it lives in
(`[tool.uv.sources]` in `pyproject.toml` names `../../awid` and
`../../naapp-lib`). The Docker build therefore needs the **repository root** as
its context; a context of `naapp/folio` cannot see those directories.

```sh
docker build -f naapp/folio/Dockerfile .    # from the aweb repository root
```

The Dockerfile copies only the paths the service needs (`awid/`,
`naapp-lib/`, and folio's `pyproject.toml`, `uv.lock`, `README.md`, `src/` and
`skills/`). Those trees are copied whole, so `naapp/folio/Dockerfile.dockerignore`
is what keeps files local to a checkout (`.env` files, virtualenvs, bytecode,
tool caches, keys) out of the build context and the image. `/app` mirrors the
repository layout (`/app/naapp/folio`, `/app/awid`, `/app/naapp-lib`), so the
path sources resolve in the image as they do in a checkout.

### Hosting service settings

A web service that builds Folio with Docker needs:

| Setting | Value |
| --- | --- |
| Repository | `github.com/awebai/aweb`, branch `main` |
| Root directory | the repository root (empty) |
| Dockerfile path | `naapp/folio/Dockerfile` |
| Docker build context | `.` (the repository root) |
| Health check path | `/health` |

A root directory of `naapp/folio` limits the build to that folder, which is why
the root directory moves to the repository root. Whether a given host resolves
the Dockerfile path and context relative to the root directory or to the
repository is host behaviour; confirm it against the host's settings before the
first build.

If the service redeploys automatically on commits, scope its build filter to
`naapp/folio/**`, `naapp-lib/**` and `awid/**`, since a change to any of them
changes the image.

### Moving an existing service onto this build

The settings change and the first deploy of a commit with this Dockerfile go
together:

1. Before the change, a build of any commit with this Dockerfile under a
   `naapp/folio` root directory fails at the first `COPY awid/...`. A failed
   build does not replace the running deploy.
2. After the change, a build of an older commit whose Dockerfile expects the
   `naapp/folio` context fails the same way. Rolling back across this change
   therefore means restoring the old settings with the old commit, unless the
   host rolls back by reusing the earlier built image.
3. Verify the new deploy with `GET /health` and an authenticated read, which
   exercises team-certificate verification through the in-repo awid.
