# aweb Conformance Tests (Black-Box)

These tests are intended to validate an `aweb` deployment *purely via its public HTTP/SSE API*.

They are **skipped by default**. To enable:

```bash
AWEB_CONFORMANCE=1 AWEB_URL=http://localhost:8000 uv run pytest -q tests/aweb_conformance
```

For a local end-to-end run (seed + server + conformance), use `scripts/run_aweb_conformance_local.sh`.

## Target selection / prerequisites

The harness needs:

- a base URL (`AWEB_URL`)
- an API key per agent identity
- at least two agents in the same project (with their own keys)

You must provide:

- `AWEB_AGENT_1_API_KEY`
- `AWEB_AGENT_1_ID`, `AWEB_AGENT_1_ALIAS`
- `AWEB_AGENT_2_API_KEY`
- `AWEB_AGENT_2_ID`, `AWEB_AGENT_2_ALIAS`

The harness will use those directly and will not call any non-specified bootstrap endpoints.

## Cross-project scoping tests

Some tests validate strict cross-project isolation. To enable them, also provide a second
project identity:

- `AWEB_OTHER_API_KEY`
- `AWEB_OTHER_AGENT_ID`, `AWEB_OTHER_AGENT_ALIAS`

## Notes

- These tests intentionally do **not** import or start the app in-process. They are black-box.
- Future beads add coverage for mail/chat/reservations semantics as specified in
  `../beadhub-sot/source-of-truth/beadhub-aweb-split.md`.
