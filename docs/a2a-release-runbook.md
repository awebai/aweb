# A2A Gateway Release Runbook

This runbook defines release sequencing, live verification, site-copy gates, and rollback posture for the aweb A2A gateway product slice described in [`a2a.md`](a2a.md) and [`a2a-awid-publication-contract.md`](a2a-awid-publication-contract.md).

The goal is a product deployment, not a hackathon-only adapter: schema-correct A2A cards, a real `aweb-a2a-gw` binary, AWID publication/delegation assertions, and live route verification before any customer-facing trust claim.

## Release Surfaces

The A2A slice can touch these release surfaces:

| Surface | Why |
|---|---|
| `awid-service` PyPI | AWID A2A publication/delegation write and read APIs, migrations, verification data. |
| `awid` GHCR | Hosted AWID service image for `api.awid.ai`. |
| `aweb` PyPI / server tag | Shared server/library code if AC imports new aweb APIs. |
| `@awebai/aw` npm | `aw a2a` CLI and packaged `aweb-a2a-gw` binary. |
| AC / Render | Hosted gateway deployment or hosted-custodial publication paths if used. |
| `site/` | Public A2A product copy after live verification only. |
| docs/skills/Pi | Operator and agent instructions if the public workflow changes. |

Hestia owns release mechanics. Do not push release tags or ask Juan to deploy from this document alone; use it as the gate checklist.

## Pre-Release Gates

Before any release handoff:

1. Athena signs off all protocol-affecting A2A changes: card schema, method names, `returnImmediately` behavior, path convention, AWID publication fields, custody/delegation model, digest bytes, and idempotency natural keys.
2. Mia signs off implementation-readiness and code slices that affect storage, publication, gateway routing, public-route security, packaging, and release sequencing.
3. `make test-a2a` passes at the exact release candidate SHA.
4. `scripts/regenerate-cli-reference.sh --check` passes at the exact release candidate SHA.
5. `git diff --check` is clean.
6. The generated `@awebai/aw` package includes both `aw` and `aweb-a2a-gw` binaries and a smoke test invokes `aweb-a2a-gw --help` from the packed artifact.
7. No site/docs/skills copy claims `verified`, `AWID-backed`, or `authorized for address` for A2A routes unless the live AWID publication and gateway verification gates below have already passed.
8. No site/docs/skills copy calls hosted A2A gateway traffic end-to-end encrypted.

## Release Order

If the release includes AWID migrations or AWID API changes:

1. Release `awid-service` first.
2. Let the GHCR image build.
3. Apply AWID migrations and deploy `api.awid.ai`.
4. Verify `api.awid.ai/health` reports the new version and all migrations are applied.
5. Smoke the A2A AWID routes directly:
   - delegation publish succeeds for a self-custodial route;
   - publication publish succeeds;
   - same active route with identical natural key returns `already_applied`;
   - same route with different `card_url`, `rpc_url`, `card_revision`, gateway, or digest returns structured 409;
   - anonymous lookup returns the active publication fields.

Only after AWID is live:

6. Release the aweb CLI/server surfaces that call the new AWID A2A APIs.
7. Verify `npm view @awebai/aw version` and install/run the exact published version.
8. From the installed package, smoke:
   - `aw a2a card <card-url>`;
   - `aw a2a publish <card-url> ...` from a self-custodial global identity workspace;
   - `aweb-a2a-gw --help`;
   - `aweb-a2a-gw --config <config> --check`.

If the release includes AC or hosted gateway deployment:

9. Deploy the gateway only after the exact published `aweb-a2a-gw` binary or image is available.
10. Confirm TLS terminates at the public host and `/.well-known/agent-card.json`, `/a2a/agents/<route>/agent-card.json`, and `/a2a/agents/<route>/rpc` are reachable.

## Live Route Publication Gate

For each public route, record:

- aweb address, e.g. `a2a.aweb.ai/research`;
- route id;
- card URL;
- RPC URL;
- card digest;
- gateway identity;
- publication assertion id;
- delegation id and digest when delegated;
- expiry;
- command transcript for `aw a2a publish`;
- command transcript for `aw a2a card --address`.

The minimum live route smoke:

```bash
aw a2a card https://a2a.aweb.ai/a2a/agents/research/agent-card.json \
  --address a2a.aweb.ai/research \
  --registry-url https://api.awid.ai

aw a2a send https://a2a.aweb.ai/a2a/agents/research/agent-card.json \
  "Return one sentence proving this A2A route reached the real aweb agent." \
  --no-wait

aw a2a status https://a2a.aweb.ai/a2a/agents/research/agent-card.json <task-id>
```

The status path must show a task state produced by the gateway from a real aweb agent reply. Do not count a gateway-only fixture response as live product verification.

## Site and Copy Gate

Olivia owns site-copy implementation. The release owner must not ask Olivia to publish A2A trust claims until:

1. Athena and Mia have approved the implementation;
2. Hestia has verified AWID and CLI release surfaces live;
3. all public routes have passed the live route publication gate;
4. gateway plaintext boundary copy is present;
5. the site copy distinguishes:
   - generic A2A interop;
   - AWID-verified publication;
   - hosted gateway plaintext boundary;
   - no E2EE claim for hosted gateway traffic.

Allowed pre-live wording:

- "A2A gateway support is in implementation."
- "Aweb uses AWID as the naming and identity layer for A2A publication."
- "Hosted A2A gateway traffic is plaintext to the gateway operator."

Blocked before live route verification:

- "verified A2A agents";
- "AWID-backed A2A routes";
- "authorized for address X";
- any wording implying hosted gateway traffic is end-to-end encrypted.

## Rollback

Allowed rollback actions:

- Disable or remove a gateway route from config.
- Set `awid_publication.required: false` only for explicitly local/unverified development routes, not public verified routes.
- Stop the gateway service.
- Roll back the gateway binary/image.
- Roll back site copy to pre-A2A or opt-in/preview wording.
- Disable new A2A publication writes at the AWID service flag if a server-side regression is found.

Forbidden rollback actions:

- Do not delete self-custodial private keys to clean up a publication.
- Do not edit shipped AWID migrations in place.
- Do not silently downgrade a public verified route to operator-configured local delegation while leaving verified/AWID-backed copy visible.
- Do not call hosted gateway traffic E2EE during rollback.

If AWID publication has succeeded but local gateway deployment fails, leave the AWID assertion intact and either fix-forward the gateway or publish a revocation assertion through the reviewed AWID path. Do not manually mutate AWID database rows.

## Verified-Live Mail

The verified-live message must include:

- exact commits and released versions for every changed surface;
- migration ids applied;
- package install smoke evidence for `aw` and `aweb-a2a-gw`;
- public card URLs and route ids;
- AWID publication assertion ids and card digests;
- one task transcript per public route proving real aweb-agent handling;
- explicit statement that hosted gateway traffic is server-readable/plaintext to the gateway;
- explicit statement of what did not ship.
