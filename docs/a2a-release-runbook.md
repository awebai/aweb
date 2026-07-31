# A2A gateway release runbook

Status: **current public maintainer runbook for the experimental OSS A2A
surface**. Owner: aweb OSS maintainers. This runbook covers the gateway binary,
AWID publication primitive, public container, self-hosted/BYOT configuration,
and public conformance evidence in this repository.

A hosted operator's route database, custody service, deployment credentials,
and production rollout are application-owned. They must have a private runbook
and are not release authority for the OSS gateway.

## Release surfaces

| Surface | Authority |
|---|---|
| Agent Card / JSON-RPC / bridge behavior | `cli/go/a2a/`, `cli/go/a2agw/`, and `docs/vectors/a2a-v1.json` / `a2a-bridge-envelope-v0.json` |
| `aw a2a` commands | `cli/go/cmd/aw/a2a.go` and live Cobra help |
| Gateway binary/image | `cli/go/cmd/aweb-a2a-gw/`, `cli/go/Dockerfile.a2a-gw`, and release workflow/Make targets |
| AWID publication/delegation | `a2a-awid-publication-contract.md`, `awid/src/awid_service/routes/a2a_publications.py`, migration `007_a2a_publications.sql`, and publication vector |
| Public operator config | `docs/examples/a2a-gateway.yaml` |

The A2A gateway is experimental. Releasing it does not move A2A into aweb's
default communication journey and does not promise persistent A2A task storage,
streaming, push notifications, or gateway E2E.

## Required pre-release gates

From a clean reviewed candidate in the aweb repository:

```bash
make test-a2a
make release-a2a-gateway-check
```

`make test-a2a` runs:

- Go card/client/gateway/AWID and conformance packages;
- A2A-focused `aw` and gateway command tests;
- AWID publication route tests; and
- the public-copy wording guard.

`make release-a2a-gateway-check` additionally builds the release Docker image,
validates the maintained public YAML inside the container, and runs the real
Docker gateway journey against aweb and AWID.

Also run:

```bash
./scripts/check-doc-paths.sh
./scripts/check-a2a-copy-guardrails.sh
git diff --check
git status --short
```

The copy guard's control is its forbidden public wording set: it fails if
non-authority copy claims verified/AWID-backed routing before the verification
gates or calls gateway traffic E2E. The source contracts are allowlisted only so
they can state those prohibitions precisely.

## Candidate evidence

Record:

- exact candidate commit from `git rev-parse HEAD`;
- exact non-merge commit count reviewed;
- `make test-a2a` and `make release-a2a-gateway-check` results;
- the gateway image tag and source repository/commit stamped into the image;
- AWID service version and confirmation that migration
  `007_a2a_publications.sql` is applied on the target registry;
- validated public config digest or the operator's reviewed derivative;
- live Agent Card URL, digest, RPC URL, route id, and publication assertion id;
- whether the route is local/unverified or AWID publication-verified; and
- rollback owner and tested removal/disable path.

Do not type or expand abbreviated hashes manually. Read exact hashes from Git at
the point they are recorded.

## Release order

When both AWID and gateway behavior change:

1. Land reviewed protocol/source/vector changes.
2. Deploy an AWID version that understands the new assertion shape and has all
   ordered migrations applied.
3. Confirm the registry `/health` response is reachable and version-compatible
   with the gateway binary.
4. Build and publish the reviewed gateway image.
5. Deploy the gateway with a dedicated workspace identity and reviewed config.
6. Publish or refresh the route/delegation only after the served card is live
   and its digest is known.
7. Verify the served card back through AWID.
8. Enable public traffic last.

Do not edit migration `007_a2a_publications.sql` after application. Every schema
change is a new ordered AWID migration.

## Image and configuration check

The release image must pass its own configuration check:

```bash
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
(
  cd cli/go
  go run ./tools/a2a-gateway-check-workspace -output "$workspace"
)
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/docs/examples/a2a-gateway.yaml:/config/gateway.yaml:ro" \
  -v "$workspace:/workspace:ro" \
  aweb-a2a-gateway:<candidate> \
  aweb-a2a-gw -config /config/gateway.yaml -workspace-dir /workspace -check
```

The generator refuses a non-empty output directory. It creates a new random
throwaway member signing key and a matching synthetic controller-signed team
certificate for
`a2a-check.invalid`; it never reads an existing workspace. The recorded server
URL points at a local refusing port and `-check` does not contact it.

Never mount a real production workspace into an unreviewed image or CI log. The
`-check` result proves parsing and gateway construction only; the Docker e2e
proves live bridge behavior.

Public/static config contains no signing key, team/namespace controller key,
API key, or bearer token. Secrets come from the dedicated workspace or named
environment inputs supported by the operator deployment.

## Live verification gate

For a route intended to be AWID-verified:

```bash
aw a2a card https://gateway.example/a2a/agents/<route>/agent-card.json \
  --address example.com/agent \
  --registry-url https://registry.example
```

The release evidence must show:

- card parses as the pinned A2A v1.0 JSON-RPC profile;
- served digest equals the active publication digest;
- served card URL equals the active publication URL;
- publication is active and unexpired;
- any delegation is active, unexpired, and digest-matched; and
- the registry accepted the signed assertion only after identity key-history
  verification.

Current `aw a2a card` does not verify Agent Card JWS. Do not report Tier-1 JWS
verification as a passing gate. Its AWID result relies on registry-verified
publication/delegation state plus the live digest and URL comparison.

For an intentionally local route without publication, label it
`operator-configured` or `local/unverified`. Do not describe it as verified,
AWID-backed, or authorized for the address.

## Plaintext boundary

The gateway terminates TLS and reads A2A task text to create the aweb bridge
message. Its process and operator can read that text. A self-hosted/BYOT
operator can place the gateway inside its own trust boundary, but that does not
turn gateway traffic into protocol E2E.

Every public card/guide/operator surface must keep this distinction:

- HTTPS protects traffic in transit to the gateway;
- aweb mail may use its own content mode after the gateway creates it;
- the gateway plaintext boundary remains;
- a future native A2A-over-aweb binding is not shipped.

## Rollback

Before deployment, prove the operator can perform each applicable rollback:

1. stop accepting new gateway tasks or disable the route;
2. roll back the gateway image to the last reviewed digest;
3. revoke or expire the AWID publication and delegation;
4. revoke/replace the dedicated gateway team certificate or identity when
   compromise is suspected; and
5. restore the previous config without reusing revoked credentials.

Disable public ingress before rotating a compromised identity. Do not delete a
self-custodial private key merely to clean up registry publication state; revoke
the public assertion/delegation through the signed AWID path.

Because the current task store is in memory, gateway restart loses A2A polling
state. Rollback communication must say this explicitly. Durable aweb mail may
still exist, but callers cannot resume a lost in-memory A2A task id after the
restart.

## Tagging and publishing

Only after exact-head review and all required gates:

```bash
make release-a2a-gateway-tag
make release-a2a-gateway-push
```

These targets create external artifacts. Confirm the tag removal/rollback path
and holder before running them. Never tag or publish from an unreviewed or dirty
worktree, and never treat a successful image push as evidence that the live
publication gate passed.
