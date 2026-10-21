# aweb secrets runner

The runner connects out to a secrets service and runs locally pinned jobs. It
uses its own signing and encryption keys; it is not an AWID team member.

This first implementation slice provides the client side of the published
[S0 protocol](../../../docs/secrets-runner-protocol.md): signed requests,
assignment verification, HPKE opening and a durable SQLite replay journal.
Registration, the command and job execution are subsequent slices of S15b.
This package does not yet execute assignments.

Verification checks the pinned service key, runner and origin, parameter and
credential hashes, and the assignment lifetime, in the protocol's specified
order. It commits the dispatch ID to the local journal before returning a
verified assignment. Invalid assignments do not consume a journal entry. An
accepted dispatch cannot be accepted by another process, including after a
restart. A crash after acceptance therefore requires reconciliation rather
than executing that dispatch again.

The journal directory must already exist, be owned by the runner UID and have
no group or other permissions. The database is created with mode 0600; symbolic
links, hard links and public files are refused. Deployment must also keep this
directory outside agent write authority. SQLite failures refuse work.

Run the focused checks from this directory:

```sh
uv sync --locked
uv run pytest tests/test_protocol.py tests/test_journal.py
uv run ruff check src tests
uv run mypy src
```

The tests consume the public protocol vectors independently of the server and
exercise real SQLite connections and child processes. Cryptographic operations
use `cryptography`, including its RFC 9180 HPKE implementation.
