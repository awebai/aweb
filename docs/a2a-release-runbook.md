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
| `a2a-gateway` GHCR | Hosted `a2a.aweb.ai` data-plane service running `aweb-a2a-gw`. |
| AC / Render | Dashboard/control-plane route management and hosted-custodial publication paths if used. |
| `site/` | Public A2A product copy after live verification only. |
| docs/skills/Pi | Operator and agent instructions if the public workflow changes. |

Hestia owns release mechanics. Do not push release tags or ask Juan to deploy from this document alone; use it as the gate checklist.

## Pre-Release Gates

Before any release handoff:

1. Athena signs off all protocol-affecting A2A changes: card schema, method names, `returnImmediately` behavior, path convention, AWID publication fields, custody/delegation model, digest bytes, and idempotency natural keys.
2. Mia signs off implementation-readiness and code slices that affect storage, publication, gateway routing, public-route security, packaging, and release sequencing.
3. `make test-a2a` passes at the exact release candidate SHA.
4. `make test-a2a-gateway-e2e` passes locally. This starts the real aweb + AWID Docker Compose backend, runs the A2A gateway container, and proves SendMessage -> real aweb mail -> agent reply -> GetTask completion.
5. `scripts/regenerate-cli-reference.sh --check` passes at the exact release candidate SHA.
6. `git diff --check` is clean.
7. The generated `@awebai/aw` package includes both `aw` and `aweb-a2a-gw` binaries and a smoke test invokes `aweb-a2a-gw --help` from the packed artifact.
8. No site/docs/skills copy claims `verified`, `AWID-backed`, or `authorized for address` for A2A routes unless the live AWID publication and gateway verification gates below have already passed.
9. No site/docs/skills copy calls hosted A2A gateway traffic end-to-end encrypted.
10. Known fixture limitation is recorded: the A2A AWID publication fixture pins canonical bytes and signed-assertion digest bytes, while real Ed25519 verification is covered by runtime AWID tests. A future release-blocking fixture upgrade should add static real-signature vectors for both publication and delegation assertions before relying on fixture-only cryptographic verification.

## Gateway Identity Provisioning

The hosted gateway is not just a static card host. It is an aweb workspace that sends bridge messages through a dedicated gateway identity, then exposes A2A cards and JSON-RPC routes for configured addresses.

Before the first Render deployment, Hestia or the release operator must create and record the production gateway identity and config:

1. Create a dedicated global gateway identity, for example `a2a.aweb.ai/gateway`, using the reviewed global identity path for the target team.
2. Accept or attach that identity to the target team with a controller-signed team certificate. The gateway must not run with a human agent's private key.
3. Confirm the gateway workspace can send an ordinary aweb message from its workspace directory before packaging the state for Render.
4. Publish the gateway identity as a normal AWID global identity where applicable. This only proves the gateway identity exists. It is not enough to call a route verified; each public route still needs its own AWID publication and delegation assertion through the live route publication gate.
5. Render the production `gateway.yaml` from [`docs/examples/a2a-gateway.yaml`](examples/a2a-gateway.yaml) or the equivalent release-owned template. The example file is not production truth and must not contain private state.
6. Deliver `gateway.yaml` and the gateway workspace state to Render as private deployment state, not as committed files. The v1 acceptable mechanism is a Render secret file or base64-encoded secret tarball expanded at startup into a private directory. The state includes `.aw/workspace.yaml`, `.aw/teams.yaml`, certificate files, `.aw/signing.key`, and local encryption key state if the workspace has one.
7. Set file permissions so private key material is readable only by the service user (`0600` files, `0700` directories where possible). The startup command must not print secrets, certificate bodies, private keys, or expanded YAML to logs.

Rotation procedure:

1. Create the replacement gateway identity and team certificate.
2. Publish or update route delegations to the replacement gateway identity.
3. Deploy Render with the replacement workspace state.
4. Verify `/health` and the live route publication gate.
5. Revoke the old route delegation and old gateway team certificate.

For suspected gateway key compromise, stop the gateway or disable public routes first, then revoke the old delegation/certificate, then deploy the replacement identity. Do not keep a compromised gateway online while relying on future route updates to limit damage.

## Release Order

If the release includes AWID migrations or AWID API changes:

1. Release `awid-service` first.
2. Let the GHCR image build.
3. Apply AWID migrations and deploy `api.awid.ai`.
4. Verify `api.awid.ai/health` reports the new version and all migrations are applied. The first A2A gateway release requires AWID migration `007_a2a_publications.sql` to be applied before the gateway deploy proceeds.
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

9. Build and publish the gateway image before creating/updating the Render service:

   `make release-a2a-gateway-check` is the narrow gateway container lane. It assumes the server, AWID, migration, and A2A release-ready checks for the same source SHA have already passed. For a fresh full release train, run the full server/AWID release-ready gates for that train before this narrow gateway check.

   ```bash
   make release-a2a-gateway-check
   make release-a2a-gateway-tag
   make release-a2a-gateway-push
   ```

   The `a2a-gw-vX.Y.Z` tag publishes:

   ```text
   ghcr.io/awebai/a2a-gateway:X.Y.Z
   ghcr.io/awebai/a2a-gateway:latest
   ```

10. Deploy `a2a.aweb.ai` as a Render Web Service backed by the gateway image, not as a static site and not as a Hetzner/systemd service for this slice. The service is the A2A data plane; it must handle JSON-RPC task calls and cannot be replaced by static card hosting. A Hetzner deployment can be revisited later only with a separate reviewed runbook.

    Render does not auto-deploy from the GHCR push. After the tag workflow publishes the image, Hestia mails Juan with the exact image tag and asks him to trigger the Render deploy manually. Hestia waits for the `/health` flip before posting verified-live.

    Minimum Render configuration:

    ```text
    Image: ghcr.io/awebai/a2a-gateway:X.Y.Z
    Port: 8080 or Render-provided $PORT
    Env:
      AWEB_A2A_GW_CONFIG=/config/gateway.yaml
    Command:
      default image command is acceptable if /config/gateway.yaml exists;
      otherwise pass: aweb-a2a-gw -config <path> -listen 0.0.0.0:$PORT
    Persistent/secret files:
      gateway YAML config
      gateway aweb workspace state with the gateway identity/cert
    ```

    The first manual deployment uses static YAML routes. The future automatic product keeps the same hosted gateway service but replaces static route config with AC-managed route/card/policy lookup. AC is the control plane; `a2a.aweb.ai` remains the data-plane gateway.

11. Confirm TLS terminates at the public host and `/.well-known/agent-card.json`, `/a2a/agents/<route>/agent-card.json`, and `/a2a/agents/<route>/rpc` are reachable.

12. Verify `https://a2a.aweb.ai/health` before marking the gateway live. Required fields:

    ```json
    {
      "status": "healthy",
      "build": {
        "release_tag": "a2a-gw-vX.Y.Z",
        "git_sha": "<release sha>"
      },
      "aweb_version": "X.Y.Z",
      "awid_service_version": ">=0.5.11",
      "awid_registry": {
        "reachable": true,
        "compatible": true,
        "version": "0.5.11",
        "minimum_version": "0.5.11"
      }
    }
    ```

    `build.release_tag` must match the pushed `a2a-gw-vX.Y.Z` tag, `build.git_sha` must match the release source SHA, `awid_registry.reachable` must be true against `api.awid.ai`, and `awid_registry.compatible` must be true. The gateway must report an AWID registry `version` or `service_version` greater than or equal to `awid_registry.minimum_version` before Hestia marks the service live.

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
   - AWID-verified publication after the live route publication gate has passed;
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
