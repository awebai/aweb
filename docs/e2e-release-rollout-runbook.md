# E2E Messaging Rollout Readiness Runbook

Status: **generic OSS maintainer procedure**, not protocol authority and not
permission to tag, deploy, or enable production traffic. The normative sources
are the [E2E messaging contract](e2e-messaging-contract.md),
[operational metadata contract](e2e-operational-metadata.md), and
[legacy/no-downgrade policy](e2e-legacy-plaintext-policy.md).

E2E is a shipped advanced, explicit `--e2ee` path. Ordinary mail/chat remains a
valid server-readable default. This runbook describes evidence required before a
maintainer makes E2E automatic, policy-required, or broadly enabled. Its feature
gates and version matrix are rollout requirements, not a claim that every gate
or preflight is currently implemented.

## Public release objective

A compatible rollout preserves these facts across every component:

- self-custodial clients encrypt/decrypt locally;
- services route ciphertext plus approved metadata;
- recipient keys come from identity-signed assertions;
- route support never substitutes for recipient key authority;
- intended E2E failures never retry as plaintext;
- hosted custody is disclosed as server-readable hosted managed encryption;
- rollback disables new E2E sends without rewriting encrypted history.

## Component readiness order

1. **Contract and vectors**
   - canonical wire/crypto contract and subordinate policies agree;
   - Python↔Go vector consumers decrypt each other's envelopes;
   - policy fixtures are parsed and completeness/forbidden-field controls pass.
2. **Identity discovery**
   - AWID publishes/verifies global identity assertions;
   - service-local discovery handles local/team identities without AWID fallback;
   - missing, stale, unsigned, mismatched, and hosted-custody assertions are
     distinguishable.
3. **Service and CLI**
   - service verifies, routes, stores, returns, and emits encrypted v2 as opaque
     content plus metadata;
   - CLI creates/archives keys, encrypts/decrypts locally, and reports structured
     failures;
   - known plaintext is absent from server rows, logs, events, APIs, bundles, and
     dumps for self-custodial test messages.
4. **Local runtimes**
   - channel/Pi/agent runtimes receive metadata-only events until local decrypt;
   - decrypt failure yields metadata/error only, never ciphertext-as-prompt or a
     plaintext retry.
5. **Hosted-custody extensions**
   - signed `custody: "hosted_custodial"` is preserved and surfaced;
   - hosted plaintext boundaries are labeled non-E2E;
   - operator-specific key storage/backfill/deploy procedure is reviewed in its
     own system, not copied into this public runbook.
6. **Federation**
   - recipient key authority and service route support are verified separately;
   - version skew and replay/idempotency cases pass against exact artifacts.

## Capability conditions

Before a route is treated as E2E-ready, establish:

- current identity-signed recipient encryption-key assertion;
- supported encrypted message version, suite, and kind;
- sender key stored locally before assertion publication;
- target service acceptance of the protected envelope;
- delivery policy authorization independent of sender-declared envelope fields.

Current senders establish recipient key authority and then rely on service
acceptance/rejection. A future complete route-capability preflight must be gated
and tested before docs claim it is universally shipped.

## Logical rollout gates

These are behavioral gates; implementations may choose different flag names.

| Gate | Enabled behavior | Safe disabled behavior |
| --- | --- | --- |
| key publication | clients publish identity-signed X25519 assertions | diagnostics say key publication unavailable |
| key discovery | senders resolve current recipient assertions | intended E2E fails before message creation |
| encrypted mail/chat send | clients construct v2 envelopes | intended E2E fails; no plaintext retry |
| service v2 acceptance | service validates/stores/routes v2 | clear unsupported response |
| metadata-only events/support | no self-custodial plaintext leaves service | keep broader E2E enablement off |
| hosted managed encryption | custody operator handles its own recipient keys | disclose unavailable hosted mode; never borrow self-custodial keys |
| explicit plaintext | user chooses server-readable mode where policy allows | no fallback from failed E2E |

## Mixed-version matrix

The machine-checkable matrix is
[`../test-vectors/e2e/mixed-version-rollout-v1.json`](../test-vectors/e2e/mixed-version-rollout-v1.json).
Every row marked `release_blocker` must be demonstrated against the exact
artifacts or staged deployment for the component being enabled.

Minimum cases:

- new sender/recipient/service: recipient and sender-copy decrypt; service has no
  plaintext;
- missing/stale recipient key: fail before storage;
- new client/old service: clear failure, no plaintext retry;
- old client/E2E-required future route: reject plaintext without storing it;
- peer route support without recipient key authority: reject;
- duplicate id/same signed envelope: idempotent same result;
- duplicate id/different envelope: reject mutation;
- stale ingress timestamp: reject, while already accepted history remains
  readable later;
- rollback: new E2E disabled, existing ciphertext and local decrypt preserved.

The current plaintext flag is `--plaintext`; `--legacy-plaintext` is a
deprecated alias. Update this runbook and the matrix together if that naming
changes.

## No-plaintext and observability gates

Allowed rollout evidence is metadata-only:

- ids, key ids, suite/version, hashes/sizes, wrap count/purpose;
- route/federation target, timestamps, delivery/read/ack state;
- safe verification/decrypt categories, counts, and latency.

Release-blocking scans cover server database rows, logs, events, API responses,
support bundles, exports, and dumps. They reject plaintext subject/body,
previews, summaries, embeddings, content-derived labels, private keys, CEKs,
auth headers, and API keys.

## Rollout phases

1. **Disabled-by-default build** — ship compatible readers/verifiers and run
   unit/vector/integration controls.
2. **Internal key/discovery validation** — exercise setup, publication, rotation,
   archive restore, and diagnostics without broad E2E policy.
3. **Limited mail canary** — explicit `--e2ee`, one-to-one, metadata/no-plaintext
   monitoring, and rollback rehearsal.
4. **Limited chat canary** — one-to-one then small groups; future wraps exclude
   explicitly removed participants. `sender_leaving` ends a turn, not membership.
5. **Federation canary** — only peers with separately verified v2 route support;
   test decrypt, reply, sender copy, replay, and plaintext absence at each peer.
6. **Broader/policy enablement** — only after the full matrix, metadata gates,
   exact-version record, artifact verification, and rollback evidence pass.

Run rollback rehearsal before leaving each phase.

## Rollback posture

Allowed:

- disable new encrypted mail/chat sends;
- keep ciphertext/metadata read paths and local decryption available;
- stop v2 federation egress to an incompatible peer;
- show clear encrypted-send-unavailable diagnostics.

Forbidden:

- rewrite encrypted messages into plaintext;
- ask routing/support services to decrypt self-custodial content;
- silently resend plaintext;
- discard archived encryption keys;
- remove replay/idempotency metadata;
- relabel legacy plaintext as encrypted v2.

A rollback after v2 history exists requires forward-compatible ciphertext reads;
it cannot make that history server-readable.

## Evidence checklist

Before any release or enablement, record:

- exact commits, versions, and artifacts for each participating component;
- ordered migrations and confirmation that applied migration baselines were not
  edited in place;
- cross-language vector, policy fixture, mixed-version, and mutation results;
- no-plaintext scan results;
- key publication/discovery and rotation/archive evidence;
- metadata-only event/support evidence;
- rollback rehearsal for the proposed phase;
- separate review for any hosted operator's custody, migration, and deployment
  procedure.

Tags, package publication, hosted deployment, and production feature switches
remain outside this documentation procedure and require the repository/operator
approval path that owns them.
