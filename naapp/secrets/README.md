# secrets

The secrets naapp lets AWID team members use credentials without holding them:
it brokers requests and runner jobs under owner-defined grants and policy, and
records every use. The design is `docs/design/secrets.md`; the build plan is
`docs/design/secrets-build-plan.md`.

This package holds secrets' own contract vectors (`vectors/`) and the tests
that consume them (`tests/`). The runner protocol is a public interop contract,
so its vector lives with the other public vectors in the repository's
`docs/vectors/`.

```bash
uv sync
make lint
make test
```

The tests need PostgreSQL, as pgdbm's test fixtures configure it.
