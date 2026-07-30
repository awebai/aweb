---
name: byot-e2e-validation
description: Use when writing e2e tests for BYOT/AWID team-certificate auth, testing aw id request --team-auth, building a docker awid-service harness, or validating replay, revocation, fail-closed, and team-scoping behavior.
---

# BYOT e2e validation

Use this when testing an agent-first app that relies on AWID team
certificates. The goal is to prove the relying-party chain works with real
keys, real certificates, real signatures, and real AWID facts.

## Iron rule: no mocked auth in e2e

No mocked certificates. No mocked signatures. No mocked AWID responses. If
you are tempted to mock one of those in e2e, you are about to test nothing.

Generate real keys and certificates with `aw id` against a local
`awid-service`. Send requests with `aw id request --team-auth`. Unit tests
can cover small parsing and interop cases, but the e2e layer must exercise
the same cryptographic and registry path a customer uses.

## Harness shape

The known-good shape in this repo is `docker-compose.e2e.yml`,
`tests/test_e2e_smoke.py`, and the `Makefile` `e2e` target:

1. Docker Compose starts Postgres, Redis, and `awid-service`.
2. `AWID_SKIP_DNS_VERIFY=1` lets tests register disposable `.test`
   namespaces locally.
3. Each test workspace gets an isolated `HOME` and clean working directory.
4. Provision through the CLI, not fixtures: `aw id create` →
   `aw id team create` → `aw id team add-member` → `aw id team fetch-cert`
   → `aw id team switch`.
5. Send the application request with `aw id request --team-auth`; never
   reimplement signing in test code.

Open finding: current `aw id request --team-auth` needs a workspace binding,
not only `.aw/teams.yaml` plus `.aw/team-certs/`. The harness writes a
minimal `.aw/workspace.yaml` after fetching the cert so the released CLI sees
an active workspace. Document this as a workaround, not as product truth. The
file contains only the test service URL, one membership (`team_id`, `alias`,
`workspace_id`, `cert_path`, `joined_at`), and workspace metadata
(`human_name`, `agent_type`, `workspace_path`, `updated_at`).

## Required negative suite

Auth-critical negatives must be hard assertions. Do not `xfail` them: an
`xfail` on auth failure can hide a regression back to 422, 500, or a bypass.

Cover at least:

- Missing envelope: assert 401.
- Replay over the wire: capture one valid request through a recording proxy,
  replay its headers/body against a different path, a different method, and a
  different audience/host; all must 401.
- Revocation: revoke the member certificate through AWID, wait for the app's
  auth cache to refresh, and assert the next request fails closed.
- Fail-closed registry outage: stop `awid-service`; assert requests still
  succeed while an unexpired cache entry exists, then fail 503/401 after
  cache expiry. Test both halves.
- Cross-team scoping: a second real team cannot read or write the first
  team's documents; naming another `team_id` in the body must not bypass the
  certificate's `team_id`.
- Raw body contracts: reject invalid UTF-8 when an endpoint accepts raw text.

Also assert attribution fields where writes create history: `did_key`, alias,
and certificate id should come from the verified signer.

## Operational hardening

Make the e2e command boring and repeatable:

- Install the teardown trap **before** `compose up`.
- Clear stale compose state before starting.
- Prefer fixture-level health waits over `docker compose --wait`; Compose
  wait behavior can be flaky with recreated or stale containers.
- Keep one documented command (`make e2e`) that starts services, runs pytest,
  and tears everything down.
- Repeated runs must pass from a dirty Docker environment.
- Expected auth failures should be asserted in test output, not left as
  unexplained log noise.

## Reference implementation

Use this repo's current harness as the working example:

- `docker-compose.e2e.yml`
- `tests/test_e2e_smoke.py`
- `Makefile` `e2e`, `e2e-up`, and `e2e-down` targets

The code is the source of truth. Keep prose thin and update it when the
harness changes.
