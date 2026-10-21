# Agent-first app pattern

`folio` is the reference BYOT relying-party app: a small service that agents
can use because they already hold an AWID team certificate. Use this repo as a
model when the user is an agent, the customer is a team, and the app should not
invent accounts.

Ground truth lives in code and tests. This doc points at it; do not fork the
contract prose unless the code and SOT move first. Paths beginning with
`naapp-lib/` are relative to the aweb repository root; other paths are relative
to `naapp/folio/`.

## The five properties folio proves

1. **Relying party, not identity provider.** The auth surface is one
   shared fail-closed verifier in `naapp-lib/src/aweb_naapp/runtime/team_auth.py`.
   Folio calls `NaappRuntime.principal`, then records the verified principal
   (`src/folio/api.py`). There are no accounts,
   OAuth flows, API keys, passwords, or sessions.
2. **The client is the `aw` CLI the agent already has.** The README recipes at
   `README.md:25-173` are the client contract. folio ships a server and docs;
   it ships zero client wrapper.
3. **Team-as-customer.** The roster is teams, not app-local users. Membership
   and revocation belong to the customer's controller and AWID registry; folio
   checks them per request (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`).
   The human appears exactly once: to pay. In v1 that payment door is absent;
   usage is measured per team and reported by `GET /v1/billing`, not capped.
4. **Validation discipline.** Unit tests cover verifier reject paths and
   byte-for-byte interop (`naapp-lib/tests/runtime/test_team_auth_envelope.py` and
   `naapp-lib/tests/runtime/test_team_auth_vectors.py`). E2E tests
   use local awid-service and real `aw id` certificates, not mocked crypto
   (`tests/test_e2e_smoke.py:376-451`, `tests/test_e2e_smoke.py:515-680`).
   The front-door recipes were validated verbatim before publication.
5. **Agent-first surface.** The FastAPI app serves the browser landing and the
   plain-text twin for agents from `src/folio/surfaces.py`, with terminal-first
   recipes, structured 401 errors (`README.md:148-173`), and append-only
   version attribution (`src/folio/repository.py:167-182`,
   `src/folio/repository.py:271-287`).

## Architecture in one page

The full auth contract is the SOT **Authentication envelope** section:
`docs/sot.md:61-126`. Link to that section rather than duplicating the ten
steps; drift in auth docs is a security bug.

The shape is:

- Agent calls `aw id request --team-auth` from a workspace with an active team
  certificate. The request carries the DIDKey Authorization header,
  `X-AWEB-Timestamp`, `X-AWID-Team-Certificate`, and
  `X-AWEB-Signed-Payload` (`docs/sot.md:70-84`).
- The service verifies the signature over the presented payload bytes, then
  independently binds the signed claims to the actual request
  (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`). Request binding covers method, raw path + raw
  query, body hash, team id, timestamp, and canonical public origin.
- AWID is authority for team public keys and certificate revocation
  (`docs/sot.md:45-59`). folio caches those public facts for performance
  (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`), for at most 60 seconds.
  Without a service token, status is cached per certificate; with a token,
  facts are cached per team. Expired facts are never a fallback after refresh failure.
- The principal's `team_id` comes from the verified certificate, not from a
  request body. Every repository query scopes by `principal.team_id`; a body
  field named `team_id` cannot write into another team (`src/folio/repository.py:139-203`,
  `tests/test_e2e_smoke.py:569-594`).
- Attribution is stored with the version: `did_key`, optional `did_aw`, address,
  alias, and certificate id (`src/folio/repository.py:167-182`,
  `src/folio/repository.py:271-287`).

## Repo map

| File | Verdict | Why |
| --- | --- | --- |
| `naapp-lib/src/aweb_naapp/runtime/team_auth.py` | **Reuse through NaappRuntime** | The shared relying-party verifier keeps request binding, AWID authority, revocation and principal construction together. Do not fork it into each app. |
| `naapp-lib/tests/runtime/` | **Read the shared verifier tests** | `test_team_auth_envelope.py`, `test_team_auth_vectors.py` and `test_awid_team_cache.py` cover request binding, interop, AWID authority, publication and revocation. Keep app integration tests in your app. |
| `src/folio/api.py` | **Adapt** | Keep the FastAPI dependency pattern that authenticates once and passes `Principal` into routes (`src/folio/api.py:28-65`). Replace document routes with your domain routes. Preserve same-origin health/API assumptions; the app serves the landing at `/`, API under `/v1/*`, and agent surfaces at `/llms.txt` and `/skills/`. |
| `src/folio/config.py` | **Adapt** | Keep `public_origin`, AWID registry URL, cache TTL, and timestamp skew knobs. Replace domain caps/settings with yours. Public origin must match what clients sign. |
| `src/folio/repository.py` | **Replace with your domain** | The team-scoping and attribution pattern is useful, but documents/versions/caps are domain code. Keep the rule: every query scopes by `principal.team_id` and writes attribute the verified member. |
| `src/folio/models.py` | **Replace with your domain** | Pydantic shapes are folio's text/billing API. Keep structured errors and response clarity; replace resource schemas. |
| `src/folio/migrations/` | **Replace with your domain** | Keep pgdbm migration discipline and immutable forward migrations. Replace tables unless your domain is also documents. |
| `tests/test_e2e_smoke.py` | **Adapt the fixture pattern** | Reuse the Docker-backed local awid-service, real `aw id` provisioning, recording proxy, revocation, fail-closed, replay-negative, and cap/error style (`tests/test_e2e_smoke.py:266-451`, `tests/test_e2e_smoke.py:597-680`). Replace endpoint assertions. |
| `docker-compose.e2e.yml` | **Copy the shape** | Local Postgres + Redis + awid-service with DNS verification disabled for `.test` namespaces is the no-mocks harness (`docker-compose.e2e.yml:1-52`). |
| `Makefile` | **Copy the shape** | Keep `test`, `e2e`, `run`, and local API serve targets. Adapt ports and service names. |
| `README.md` | **Adapt, but keep recipes literal** | The README is the client contract. Recipes must be run verbatim before publication (`README.md:25-173`). Do not document blind copy-all when the setup has stop points. |
| `src/folio/surfaces.py` | **Adapt the pattern** | Text-first human and agent surfaces served by the app: landing, reference, `/llms.txt`, `/skills/`, robots, and no private JS framework dependency. Keep it concise and command-oriented. |
| `docs/sot.md` | **Write your own first** | This is the worked example of the source-of-truth doc: product, authority, envelope, data, API, validation, milestones. Your app needs its own SOT before code. |
| `skills/team-cert-verification/SKILL.md` | **Use when integrating auth** | Load it when adopting or reviewing the shared verifier. It points to naapp-lib and the SOT. |

## Process that worked

1. Write the SOT first; make authority, auth, data, API, validation, and
   non-goals explicit.
2. Cut an epic into small tasks with acceptance criteria.
3. TDD each behavior, especially auth reject paths.
4. Keep e2e no-mocks: local awid-service, real `aw id` identity/team/cert,
   real `aw id request --team-auth`.
5. Require independent review before merge.
6. Push the branch; reviewers cannot review an unpushed worktree.
7. Coordinator verifies on merged main, not only on the feature branch.
8. Validate published recipes verbatim from a fresh workspace.
9. Gate deploy on the human-owned domain/target decision.
10. Before public claims, do a front-door probe with released `aw` only.

## Pitfalls we hit or designed against

| Pitfall | What to do instead |
| --- | --- |
| Verifying the certificate against its own `team_did_key` field. | Resolve the team key from AWID and verify against that (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`). The cert field is data, not authority. |
| Using the router-normalized path. | Use raw on-the-wire path + query from ASGI `raw_path` and `query_string` (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`). Percent encoding and query order matter. |
| Reconstructing a payload for signature verification. | Verify the DIDKey signature over decoded `X-AWEB-Signed-Payload` bytes (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`). Then compare claims to the request. |
| Trusting cache past expiry when AWID is down. | Use unexpired cache only; after expiry fail closed with 503 (`naapp-lib/src/aweb_naapp/runtime/team_auth.py`, `tests/test_e2e_smoke.py:623-640`). |
| Documenting commands that were never run verbatim. | Run each line from a fresh workspace and record the response. If setup has stop points, do not promise copy-all. |
| Mocked crypto in e2e. | Provision real namespaces, teams, and certificates with `aw id`; send real signed requests (`tests/test_e2e_smoke.py:376-451`). |
| A hidden fallback auth path for testing. | Do not add API keys, sessions, dashboard write paths, or trusted headers. Test the same verifier production uses. |
| `.aw/workspace.yaml` binding wrinkle in fresh e2e workspaces. | Open finding: the current e2e fixture writes the workspace binding explicitly after fetching the cert (`tests/test_e2e_smoke.py:356-373`). Be explicit if your harness still needs that bridge. |
