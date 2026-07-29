# library

`library.aweb.ai` is the agent-first service that owns **agent profiles** for
AWID teams: reusable blueprints, individual profiles with versions and
content digests, agent-profile bindings, materialization payloads for local and
custodial runtimes, and profile learning proposals.

It follows the folio/atext app pattern: a standalone service with AWID
team-certificate auth for team-scoped operations, public metadata endpoints for
first-party blueprints, an app manifest for `aw`/gateway dispatch, and `/llms.txt` +
`/skills/`. There is no app-specific human account system — AWID is the login.
AC does not authorize library; library owns its own state.

Open source, MIT-licensed — [github.com/awebai/library](https://github.com/awebai/library).

## Status

Scaffold (`default-aaas.14.1`): the service boots, enforces AWID
team-certificate auth on team-scoped routes, and serves the manifest,
`/llms.txt`, and `/skills/`. The public catalog reads return empty results and
the team-scoped write routes are cert-auth-gated `501` stubs. The profile/blueprint
model, real endpoint bodies, and domain tables arrive in later tasks.

## Endpoints

Public (no auth):

- `GET /` — landing page
- `GET /llms.txt`, `GET /skills/`
- `GET /aweb-app.json`, `GET /.well-known/aweb-app.json` — app manifest
- `GET /v1/blueprints`, `GET /v1/blueprints/{blueprint_id}`, `GET /v1/profiles/{profile_id}`

Team-scoped (AWID team certificate):

- `POST /v1/blueprints/import`
- `POST|GET /v1/agents/{agent_id}/profile-binding`
- `POST /v1/materialize`
- `POST|GET /v1/proposals`, `POST /v1/proposals/{proposal_id}/approve|reject`

## Development

```bash
uv sync
uv run pytest -m "not e2e"
uv run ruff check src tests
uv run mypy src/library
```

The e2e suite (`-m e2e`) is docker-backed and uses real `aw`/AWID tooling.

## Continuous integration

Pull requests and pushes to `main` run the `Lint, test, and real-stack e2e`
check. Branch protection requires that exact check before merging to `main`,
including for administrators.

The break-glass path for an emergency fix while CI itself is broken is to get
repository-owner approval, temporarily disable the required protection, land
only the emergency fix, and immediately re-enable the same protection. Record
both the disable and re-enable actions, with their timestamps and reason, in a
shared task or incident. Administrator bypass is not the break-glass path.

## Production operations

Reviewed Render deploy, verification, rollback, and recovery targets are documented in
[`docs/production-operations.md`](docs/production-operations.md). Production mutations
must use those checked-in Make targets rather than ad-hoc commands.

## License

MIT. See [LICENSE](LICENSE).
