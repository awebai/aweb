---
type: Decision
title: The server takes the published aweb-naapp; the frozen naapp copies test against published aweb
description: Once the server's naapp floor rises above the frozen in-repo naapp-lib, the server's dev sources move to the published aweb-naapp and aweb-naapp-testing, and the frozen packages drop their aweb path source instead of being bumped or removed; the switch reaches pyproject, Dockerfile, server CI, PRODUCTION_AWID_PROJECT and every lock that takes both the server and the frozen copy.
tags: [decision, naapp, dependencies, release, locks, server]
timestamp: 2026-11-27
---

Chosen by the OSS coordinator on 2026-11-27 for server 1.27.56, which needs
`aweb-naapp[egress,hooks]>=0.6.0` (the first published release with
`EgressUnresolved`). aweb's in-repo naapp copies are frozen and leaving, and
the in-repo naapp-lib stays at 0.5.2. With that version it cannot satisfy the
floor. Status at harvest: the landing commit (server 1.27.56, 29e05ff913) sat
on a branch on top of main 9adbca101 and was not yet on main.

# Decision

- The server's dev sources are the published `aweb-naapp` and
  `aweb-naapp-testing`, not `../naapp-lib`. The image and the gate then run
  what customers install.
- The frozen packages that took aweb from `../server` drop that path source and
  test against the last published aweb: naapp-lib, naapp-lib/testing and
  naapp/secrets. The frozen code itself is untouched.

# Rejected

- **Bumping the frozen naapp-lib copy:** it pulls naapp main into a copy meant
  to stay put.
- **Removing the frozen copies now:** that is the copies' own removal step, too
  large to bundle into a security release.

# What the switch touches

The next naapp floor raise, and the eventual removal of the copies, hit the
same surface. Grep every `naapp-lib` reference, not only pyproject:

- `server/pyproject.toml` `[tool.uv.sources]`.
- `server/Dockerfile`, which copied naapp-lib into the builder and the image.
- `server-ci.yml`, which built a naapp-lib wheel into the smoke install. That
  wheel would then conflict with the floor.
- `PRODUCTION_AWID_PROJECT` must be exported as an absolute path.
  `aweb_naapp_testing.production_registry` defaults to a path relative to its
  own file, and that path only resolves for the editable copy inside aweb. The
  Makefile's own relative value overrides an environment variable and breaks
  under `server/`.
- Every lock that takes both the in-repo server and the frozen naapp-lib
  becomes unsatisfiable: naapp-lib, naapp-lib/testing, naapp/logs (through
  naapp-lib/testing, because uv applies a path dependency's own
  `[tool.uv.sources]`) and naapp/secrets. naapp/folio's lock metadata changes
  too. `check-python-locks` reports it.

# Checking the next naapp version

List the names the server imports from naapp (an AST scan of `server/src`) and
compare their signatures. Then take the import closure of those modules and
AST-compare it with docstrings stripped: formatting differs between the two
repositories, so a text diff is useless. Finally, run the server's
naapp-touching tests with its uv sources pointed at the candidate. For 0.6.0,
this found one moved test-only import (`app_request_credential`, now in
`runtime.app_credentials`) and one runtime difference, the default resolver of
`DnsResolver`.

`make test-naapp` ends with `git diff --exit-code` on the package lock. Run
before a relock is committed, it fails after the tests pass, so read pytest's
totals and not the exit code.

# Evidence

Focused server tests: 1003 passed on published aweb-naapp 0.6.0. naapp-lib
(5114) and naapp/logs (474) passed against published aweb 1.27.55. naapp/secrets
was not run locally, and the release gate covers it.

Evidence: OKF proposal from aweb-expert/aweb-expert-sec-r1, 2026-11-27;
notes/server-against-published-naapp.md.
