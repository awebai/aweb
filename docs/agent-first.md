# Agent-first app pattern

`folio` is the reference BYOT relying-party app: a small service that agents
can use because they already hold an AWID team certificate. Use this repo as a
model when the user is an agent, the customer is a team, and the app should not
invent accounts.

Ground truth lives in code and tests. This doc points at it; do not fork the
contract prose unless the code and SOT move first.

## The five properties folio proves

1. **Relying party, not identity provider.** The auth surface is one
   fail-closed verifier of AWID team certificates: `src/folio/auth.py:50-100`
   resolves team facts, `src/folio/auth.py:176-222` binds the signed request,
   and `src/folio/auth.py:238-301` builds the principal. There are no accounts,
   OAuth flows, API keys, passwords, or sessions.
2. **The client is the `aw` CLI the agent already has.** The README recipes at
   `README.md:25-173` are the client contract. folio ships a server and docs;
   it ships zero client wrapper.
3. **Team-as-customer.** The roster is teams, not app-local users. Membership
   and revocation belong to the customer's controller and AWID registry; folio
   checks them per request (`src/folio/auth.py:58-100`, `src/folio/auth.py:283-289`).
   The human appears exactly once: to pay. In v1 that payment door is absent and
   the structured 402 says subscriptions are not yet available
   (`src/folio/repository.py:23-34`, `docs/sot.md:128-145`).
4. **Validation discipline.** Unit tests cover verifier reject paths and
   byte-for-byte interop (`tests/test_auth_v2_envelope.py:208-343`). E2E tests
   use local awid-service and real `aw id` certificates, not mocked crypto
   (`tests/test_e2e_smoke.py:376-451`, `tests/test_e2e_smoke.py:515-680`).
   The front-door recipes were validated verbatim before publication.
5. **Agent-first surface.** The browser site has a plain-text twin for agents
   (`site/static/llms.txt:1-64`), terminal-first recipes, structured 401/402
   errors (`README.md:148-173`), and append-only version attribution
   (`src/folio/repository.py:167-182`, `src/folio/repository.py:271-287`).

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
  (`src/folio/auth.py:176-222`). Request binding covers method, raw path + raw
  query, body hash, team id, timestamp, and canonical public origin.
- AWID is authority for team public keys and certificate revocation
  (`docs/sot.md:45-59`). folio caches those public facts for performance
  (`src/folio/auth.py:50-100`), but cache is not product authority.
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
| `src/folio/auth.py` | **Copy verbatim** | This is the relying-party verifier. Keep the cache, raw target, canonical audience, signature-over-presented-payload, AWID-resolved team key, revocation, and principal construction together (`src/folio/auth.py:50-301`). |
| `tests/test_auth_v2_envelope.py` | **Copy + keep green** | This is the verifier spec by example: reject paths, replay negatives, raw-path/root-path parity with `aweb.team_auth_envelope`, AWID-key enforcement, revocation, and interop vectors (`tests/test_auth_v2_envelope.py:208-343`). Port it with `auth.py`. |
| `src/folio/api.py` | **Adapt** | Keep the FastAPI dependency pattern that authenticates once and passes `Principal` into routes (`src/folio/api.py:28-65`). Replace document routes with your domain routes. Preserve same-origin health/API assumptions; deploy serves static site at `/`, API under `/v1/*`. |
| `src/folio/config.py` | **Adapt** | Keep `public_origin`, AWID registry URL, cache TTL, and timestamp skew knobs. Replace domain caps/settings with yours. Public origin must match what clients sign. |
| `src/folio/repository.py` | **Replace with your domain** | The team-scoping and attribution pattern is useful, but documents/versions/caps are domain code. Keep the rule: every query scopes by `principal.team_id` and writes attribute the verified member. |
| `src/folio/models.py` | **Replace with your domain** | Pydantic shapes are folio's text/billing API. Keep structured errors and response clarity; replace resource schemas. |
| `src/folio/migrations/` | **Replace with your domain** | Keep pgdbm migration discipline and immutable forward migrations. Replace tables unless your domain is also documents. |
| `tests/test_e2e_smoke.py` | **Adapt the fixture pattern** | Reuse the Docker-backed local awid-service, real `aw id` provisioning, recording proxy, revocation, fail-closed, replay-negative, and cap/error style (`tests/test_e2e_smoke.py:266-451`, `tests/test_e2e_smoke.py:597-680`). Replace endpoint assertions. |
| `docker-compose.e2e.yml` | **Copy the shape** | Local Postgres + Redis + awid-service with DNS verification disabled for `.test` namespaces is the no-mocks harness (`docker-compose.e2e.yml:1-52`). |
| `Makefile` | **Copy the shape** | Keep `test`, `e2e`, and site build targets (`Makefile:7-25`). Adapt ports and service names. |
| `README.md` | **Adapt, but keep recipes literal** | The README is the client contract. Recipes must be run verbatim before publication (`README.md:25-173`). Do not document blind copy-all when the setup has stop points. |
| `site/` | **Adapt the pattern** | Static, text-first, no JS frameworks or analytics. Landing page explains agent-first inversion; docs mirror validated recipes. |
| `site/static/llms.txt` | **Adapt the pattern** | Plain-text twin for agents that fetch instead of browse (`site/static/llms.txt:1-64`). Keep it concise and command-oriented. |
| `docs/sot.md` | **Write your own first** | This is the worked example of the source-of-truth doc: product, authority, envelope, data, API, validation, milestones. Your app needs its own SOT before code. |
| `skills/team-cert-verification/SKILL.md` | **Copy/use when porting auth** | Load it when implementing or reviewing a verifier. It is the checklist version of `auth.py` plus SOT. |

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
| Verifying the certificate against its own `team_did_key` field. | Resolve the team key from AWID and verify against that (`src/folio/auth.py:283-289`). The cert field is data, not authority. |
| Using the router-normalized path. | Use raw on-the-wire path + query from ASGI `raw_path` and `query_string` (`src/folio/auth.py:149-173`). Percent encoding and query order matter. |
| Reconstructing a payload for signature verification. | Verify the DIDKey signature over decoded `X-AWEB-Signed-Payload` bytes (`src/folio/auth.py:186-220`). Then compare claims to the request. |
| Trusting cache past expiry when AWID is down. | Use unexpired cache only; after expiry fail closed with 503 (`src/folio/auth.py:58-87`, `tests/test_e2e_smoke.py:623-640`). |
| Documenting commands that were never run verbatim. | Run each line from a fresh workspace and record the response. If setup has stop points, do not promise copy-all. |
| Mocked crypto in e2e. | Provision real namespaces, teams, and certificates with `aw id`; send real signed requests (`tests/test_e2e_smoke.py:376-451`). |
| A hidden fallback auth path for testing. | Do not add API keys, sessions, dashboard write paths, or trusted headers. Test the same verifier production uses. |
| `.aw/workspace.yaml` binding wrinkle in fresh e2e workspaces. | Open finding: the current e2e fixture writes the workspace binding explicitly after fetching the cert (`tests/test_e2e_smoke.py:356-373`). Be explicit if your harness still needs that bridge. |
