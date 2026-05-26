# E2E Messaging Release Rollout Runbook

This runbook defines release sequencing, mixed-version behavior, rollout gates,
observability, and rollback posture for encrypted message v2. It is subordinate
to the normative protocol contract in
[`e2e-messaging-contract.md`](e2e-messaging-contract.md) and the operational
metadata contract in
[`e2e-operational-metadata.md`](e2e-operational-metadata.md). If this runbook
conflicts with those contracts, stop the rollout and route the conflict back
through the relevant `aweb-aapv` contract review instead of shipping a local
exception.

This is a release/ops plan, not permission to publish, tag, deploy, or enable
production traffic. Hestia owns release mechanics before tags are pushed.

## Release objective

Ship encrypted message v2 so local clients encrypt/decrypt message content while
AC/aweb servers route ciphertext plus approved metadata. Mixed-version clients,
servers, hosted surfaces, and federation peers must fail closed rather than
silently sending plaintext when an intended encrypted send cannot be completed.

## Release train components

Exact semver/tag numbers are filled by the release owner after implementation
commits are selected. The train should move in this order:

1. **Contract baseline**
   - `aweb` docs: `docs/e2e-messaging-contract.md`.
   - `aweb` docs: `docs/e2e-operational-metadata.md`.
   - Release gate: Mia support/implementation review and Athena metadata review
     are complete for the docs in the release branch.
2. **AWID / identity authority**
   - Encryption-key assertion publication/discovery.
   - Identity-authorized key facts; service signatures may assert route support
     only, not recipient key authority.
   - Release gate: key discovery can distinguish supported, missing assertion,
     stale assertion, unsigned assertion, and mismatched identity.
3. **aweb server + `aw` CLI**
   - Server accepts, verifies, routes, stores, returns, and emits events for v2
     encrypted envelopes as opaque ciphertext plus metadata.
   - CLI/client creates encryption keys, signs key assertions, encrypts,
     decrypts locally, verifies inner-header/hash/signature binding, and reports
     structured failures.
   - Release gate: no known plaintext string appears in server DB rows, logs,
     SSE payloads, dashboard/API responses, support bundles, DB dumps, or release
     artifacts for v2 test messages.
4. **AC/dashboard and hosted surfaces**
   - Remove, hide, or downgrade plaintext mail/chat views for v2 encrypted
     content.
   - Hosted custodial MCP, dashboard-side compose/read, and other server-side
     tools remain labeled **server-readable hosted messaging**, not encrypted v2
     local-client messaging.
   - Release gate: dashboard/API/support surfaces show metadata-only or a clear
     blocked/unavailable state for v2 plaintext.
5. **Channel, Pi, `aw run`, skills, and package docs**
   - Channel events are metadata-only until local decryption succeeds.
   - Pi/skills/docs explain local decryption, key loss, no silent plaintext
     fallback, and server-readable hosted exceptions.
   - Release gate: package docs and canonical skills use the same boundary words
     as the release branch docs.
6. **Federation enablement**
   - Federated peers advertise v2 route support separately from recipient
     encryption-key authority.
   - Release gate: version skew cases in the mixed-version matrix pass against
     the exact release artifacts or staged deployments.

## Capability and feature gates

Use additive capability signals. Do not infer encrypted-message support from a
new binary version alone.

Required capability facts before a sender may send v2:

- recipient identity has a current identity-authorized encryption-key assertion,
- recipient route advertises support for `message_version = 2` and the requested
  kind (`mail` or `chat`),
- sender local client has generated and stored its encryption key before
  publishing an assertion,
- server route accepts the configured suite,
- policy requires encrypted v2 or permits the explicit named legacy plaintext
  escape hatch.

Feature gates should be independently disableable:

| Gate | Meaning when enabled | Safe disabled behavior |
| --- | --- | --- |
| `e2ee_key_publish` | clients may publish identity encryption-key assertions | receive/send v2 is unavailable; diagnostics name missing key setup |
| `e2ee_key_discovery` | senders may discover recipient encryption keys/capability | intended encrypted sends fail closed before message creation |
| `e2ee_send_mail` | clients may create v2 mail envelopes | intended encrypted sends fail closed; no plaintext retry |
| `e2ee_server_accept_mail` | server accepts v2 mail envelopes | server rejects v2 clearly; sender does not downgrade automatically |
| `e2ee_events_metadata_only` | server emits metadata-only v2 events | keep v2 production send disabled until this is true |
| `e2ee_dashboard_metadata_only` | dashboard/support surfaces avoid v2 plaintext | keep v2 production send disabled until this is true |
| `legacy_plaintext_escape_hatch` | explicit user-selected legacy mode remains available where policy allows | no implicit fallback; old senders follow legacy policy |

Gate names are descriptive placeholders for rollout/runbook discussion; final
flag names may differ, but their disabled behavior must preserve fail-closed
semantics.

## Minimum compatibility rule

A client/server pair is compatible for encrypted v2 only when both sides confirm
support for the same envelope version, suite, message kind, route support, and
identity-authorized recipient encryption key. Otherwise the result is a
structured failure before plaintext crosses a server boundary.

Do not publish a broad rollout until the release owner records the exact minimum
compatible versions for:

- `awid` / registry service,
- `aweb` server package,
- `aw` CLI,
- AC/dashboard backend/frontend,
- channel/Pi/`aw run` packages,
- canonical skills / packaged skills,
- any federated peer deployments included in the rollout.

## Mixed-version matrix

The fixture at
[`../test-vectors/e2e/mixed-version-rollout-v1.json`](../test-vectors/e2e/mixed-version-rollout-v1.json)
contains the machine-checkable version of this matrix. Every row is a release
blocker for the relevant component before broad enablement.

| Case | Expected behavior | Release-blocking assertion |
| --- | --- | --- |
| new sender, new recipient, new server | v2 encrypted send succeeds | recipient decrypts locally; sender self-copy decrypts; server stores no plaintext |
| new sender, old recipient or missing recipient key assertion | send fails before storage | failure names missing/stale/unsupported key capability; no plaintext row/event |
| old sender, new recipient | legacy plaintext may arrive only if recipient/team policy still allows it | message is labeled legacy plaintext and never claimed as v2 |
| new client, old server | v2 send fails clearly | client does not retry plaintext silently |
| old client, new server on encrypted-required route | server rejects legacy plaintext | no plaintext row is stored |
| old hosted server-readable MCP/dashboard sender, new local encrypted recipient | hosted/server-readable path is not treated as encrypted v2 | UI/copy labels server-readable mode; no encrypted-product claim |
| new sender, federated peer lacks v2 route support | send fails before delivery | route-support failure is distinct from recipient key failure |
| new sender, peer claims route support but recipient key assertion is missing/stale/unsigned | send fails before storage/delivery | service route support does not substitute for recipient key authority |
| duplicate `message_id`, same signed envelope | idempotent success or same-result response | stored envelope hash matches original |
| duplicate `message_id`, different signed envelope | replay/mutation rejection | no second row, no event with mutated metadata |
| stale timestamp at ingestion | reject at ingress | already-accepted stored mail remains readable later |
| rollback after v2 messages exist | v2 send disabled; existing encrypted history remains retrievable as ciphertext/metadata | rollback does not convert intended encrypted messages to plaintext |

## Failure messages

Failure messages must be specific enough for support and agents to choose the
right next step without encouraging plaintext fallback:

- missing local encryption private key,
- missing published encryption-key assertion,
- stale encryption-key assertion,
- unsigned or identity-mismatched assertion,
- route lacks v2 support,
- old client or old server,
- unsupported suite,
- malformed ciphertext or key wrap,
- replay or idempotency conflict,
- inner-header mismatch,
- explicit legacy plaintext mode required but not selected.

The message should say that no plaintext fallback occurred. If legacy plaintext
is allowed, it must be a separate explicit command/UX path named as legacy
plaintext and visually distinct from encrypted v2. If the product renames the
legacy plaintext flag or UX label in a future release, update this runbook and
[`../test-vectors/e2e/mixed-version-rollout-v1.json`](../test-vectors/e2e/mixed-version-rollout-v1.json)
in the same change so release tests and user-facing naming stay aligned.

## Observability and support gates

Operational observability uses only the metadata allowed in
[`e2e-operational-metadata.md`](e2e-operational-metadata.md):

- encryption version, suite, message kind,
- message/conversation ids,
- sender/recipient ids, key ids, route kind, delivery origin, federation peer,
- ciphertext hash and bytes, envelope bytes, key-wrap count, wrap purposes,
- delivery/read/ack/failure states,
- verification/decryption error categories,
- usage/billing counters, abuse/rate-limit signals, and support request ids.

Release blockers:

- support/admin endpoints either return metadata/ciphertext only or a clear
  blocked response for v2 plaintext,
- support bundles contain no plaintext, previews, summaries, embeddings,
  content-derived labels, private keys, archived encryption keys, API keys, auth
  headers, or decrypted exports unless the user intentionally attaches a support
  export as a separate artifact,
- billing and abuse dashboards do not include content-derived categories for v2,
- dashboard/conversation lists do not generate server-side plaintext previews.

## Rollout phases

1. **Dark launch**
   - Ship code paths disabled by default.
   - Run fixture, unit, and integration gates in CI.
   - Verify docs/skills/package wording in release branch.
2. **Internal canary**
   - Enable key publication/discovery and local decrypt diagnostics for internal
     self-custodial workspaces only.
   - Keep broad v2 send disabled until metadata-only events/dashboard/support
     gates pass.
3. **Limited encrypted mail canary**
   - Enable one-to-one mail for a named internal team or allowlist.
   - Monitor metadata-only delivery, decrypt error categories, no-plaintext
     scans, support bundle output, and rollback rehearsals.
4. **Federation canary**
   - Enable only peers that advertise v2 route support and have passed the
     matrix cases.
   - Treat route support as separate from recipient key authority.
5. **Broader enablement**
   - Release owner records exact versions, flags, test evidence, Hestia release
     mechanics review, Mia implementation/support review, Athena metadata
     allowance, and any AC/dashboard approvals.

## Rollback posture

Rollback must disable new encrypted sends without corrupting encrypted history or
enabling unsafe downgrade.

Allowed rollback actions:

- disable `e2ee_send_mail` or equivalent send gate,
- keep read paths for already-stored v2 ciphertext/metadata available,
- keep local decryption available in clients that already have keys,
- stop federation v2 egress to a peer whose route support is failing,
- show clear “encrypted send unavailable” diagnostics.

Forbidden rollback actions apply across server rollback, clients, and agents
participating in the release response. Servers cannot ask for these actions, and
clients/agents must not perform them during a panic rollback:

- rewrite encrypted messages into plaintext,
- ask the server/support to decrypt,
- silently resend a failed encrypted message as plaintext,
- discard archived encryption key material,
- remove metadata needed for idempotency/replay/mutation checks,
- relabel legacy plaintext as encrypted v2.

If a release must roll back after users have sent v2 messages, keep a forward-fix
plan for read/decrypt compatibility. Message history remains encrypted content
plus metadata; rollback cannot make it server-readable.

## Release evidence checklist

Before tags or production enablement, collect and link:

- exact commits and package versions for every release train component,
- migration list and confirmation no existing migration baseline was edited for
  additive schema changes,
- mixed-version matrix results from the release artifacts,
- no-plaintext scan results for DB rows, logs, SSE events, dashboard/API
  responses, support bundles, DB dumps, and release artifacts,
- metadata-only billing/usage/support fixture validation,
- rollback rehearsal notes,
- Hestia release-mechanics review,
- Mia implementation/support review,
- Athena metadata allowance review,
- AC/dashboard review for server-readable hosted surface wording and plaintext
  surface removal.

## Ownership

- Release owner / Hestia: tags, package publish, deploy sequencing, rollback
  decision, final version table.
- Grace: `aweb-aapv` epic sequencing and cross-slice contract integrity.
- Mia: implementation-readiness and support/admin wording review.
- Athena: cryptographic/metadata allowance review.
- Slice owners: provide tests/evidence for the rows and gates touched by their
  slice before requesting rollout inclusion.
