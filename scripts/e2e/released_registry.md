# Published old-registry fixture

`released_registry.py` starts the actual published `awid-service 0.5.39`
package. It checks the wheel hash, installed version and every bundled `awid/`
and `awid_service/` file before executing the stock standalone factory. It does
not simulate a missing protection field or mount candidate registry code.

Prepare once in the lab runner, with Python 3.12 and the frozen published wheel:

```sh
uv venv --python 3.12 /lab/old-registry
uv pip install --python /lab/old-registry/bin/python --require-hashes \
  -r scripts/e2e/fixtures/awid-0.5.39-requirements.txt
uv pip install --python /lab/old-registry/bin/python --no-deps \
  /lab/inputs/awid_service-0.5.39-py3-none-any.whl
/lab/old-registry/bin/python -I scripts/e2e/released_registry.py \
  --wheel /lab/inputs/awid_service-0.5.39-py3-none-any.whl \
  --receipt /lab/evidence/old-registry-package.json --check-only
```

The requirements are `uv export --frozen --no-dev --no-emit-project --no-header`
from `awid/uv.lock` at `awid-service-v0.5.39`. Dependencies are hash-checked; the
launcher pins the wheel to SHA256
`41238e71d92cbe9ad5be9bb7f1ffa317ed9d55e0db7255e2599832c8ad43de30`.
Do not install the candidate editable package in this environment. Its own
interpreter and `-I` avoid inherited checkout/user-site imports. The receipt
records actual package roots, file hashes and dependency versions without DB
credentials.

Give the fixture a **fresh, disposable PostgreSQL database**, with
`CREATE EXTENSION pgcrypto WITH SCHEMA public` run before startup, and a
dedicated Redis database. Do not reuse a database that has newer migrations or
has ever been provisioned for protection. Standard lab ownership and cleanup
apply to both. Startup uses the installed package's migrations 001–011 and its
normal `schema_migrations` table; it does not apply candidate migrations.

The process requires these environment variables:

| Variable | Meaning |
| --- | --- |
| `AWID_DATABASE_URL` | Private disposable PostgreSQL DSN |
| `AWID_REDIS_URL` | Private dedicated Redis database |
| `AWID_DB_SCHEMA` | Distinct lower-case schema, e.g. `old_registry` |
| `AWID_PUBLIC_ORIGINS` | The registry's actual external origin, used for covering signatures |
| `AWID_SERVICE_TOKEN` | Optional disposable service-to-service read token; never a production token |

Run the same command without `--check-only`, with `--host 0.0.0.0 --port 8010`
when used on a private lab network. Keep PostgreSQL and Redis private. A TLS
front supplied by the common DNS/CA topology may expose the stock listener;
do not alter response bodies. `/health` or `/ready` returns 200 only when both
dependencies work; it reports version `0.5.39`, the schema and the actual
limiter class. `/live` checks only process liveness.

The launcher removes inherited candidate/development settings and forces the
stock Redis limiter. It does not disable quotas or supply a trusted service
token automatically. Give distinct cases their own Redis DB/stack rather than
resetting limiter state during a case. Preserve actual 429/5xx and transport
failures as such; they do not establish an older registry.

Authority stays in the old routes. Namespace registration requires the real
namespace/DNS authority; team creation requires its namespace controller's
covering signature; certificate registration/revocation requires the team's
controller. Private team reads require an unrevoked member/controller path
signature or the separately configured service token. Public reads need no
such token. The fixture does not seed any authority or provide a bypass.

An already frozen production image can alternatively provide the old process
environment:
`ghcr.io/awebai/awid@sha256:35be32f8f26234ff217ee37c70d732590c83b21def02e0298c72197d235238c5`
(amd64 manifest
`sha256:dfba6ec52fa4ff2e67cd127314fc501ab33288fbbed47779289743207e383d85`).
Mount the launcher and wheel read-only, a writable receipt directory owned by
the image's uid 1001, and invoke `/app/.venv/bin/python -I` with the same
arguments/environment. Its installed files must still pass the wheel check.
This is an alternative installation of the same fixture, not a second route
harness. An image digest or a check-only receipt alone is not a runtime result.
