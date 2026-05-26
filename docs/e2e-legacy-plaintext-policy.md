# E2E Legacy Plaintext and No-Downgrade Policy

This document defines how existing plaintext mail/chat and explicit
server-readable modes coexist with encrypted message v2. It is subordinate to
[`e2e-messaging-contract.md`](e2e-messaging-contract.md) and
[`e2e-operational-metadata.md`](e2e-operational-metadata.md). If this document
appears to change crypto, envelope, key-authority, or metadata-leakage rules,
stop and route the change back through `aweb-aapv.1` review.

## Content Modes

Every mail/chat item must be classified with an explicit content mode:

| Mode | Meaning | Plaintext visible to AC/aweb server? |
| --- | --- | --- |
| `legacy_plaintext_v1` | Historical or explicitly requested plaintext messaging using the v1 subject/body shape. | Yes. |
| `encrypted_v2` | E2E encrypted message v2 from the E2E contract. | No, except customer-provided support exports. |
| `server_readable_hosted` | Hosted custodial MCP, dashboard compose/read, or any other server-side mode where plaintext enters AC/aweb. | Yes, by design. |

The mode is not cosmetic. It determines storage, API response shape, dashboard
rendering, support workflow, retention, and send failure behavior.

## Existing Plaintext History

Existing v1 plaintext history cannot become E2E retroactively. A migration may
keep it readable, export it, redact it after a window, or let customers purge it,
but product copy and APIs must not relabel it as encrypted.

Required display label for retained legacy content:

`Legacy plaintext: this message was stored server-readable before E2E encryption.`

The exact UI wording may be shorter, but it must preserve these facts:

- the message is legacy/plaintext,
- it was or is server-readable,
- it is not E2E encrypted.

Legacy plaintext search and previews may continue only over
`legacy_plaintext_v1` rows while that mode remains retained. Search/previews over
`encrypted_v2` subject/body are forbidden server-side.

## No-Downgrade Rule

An intended E2E send must fail closed when any required E2E condition is absent:

- missing recipient identity-authorized encryption key assertion,
- stale, expired, unsigned, mismatched, or unsupported encryption-key assertion,
- recipient identity or route lacks E2E capability,
- server route does not accept `message_version = 2`,
- suite/version mismatch,
- old client or old server cannot prove it understands v2,
- sender/recipient policy requires E2E and any legacy fallback is suggested.

The client must not automatically retry as plaintext after an E2E failure. The
server must not hint "retry as plaintext" for an E2E route. Federation peers must
not translate v2 to v1.

## Explicit Legacy Plaintext Escape Hatch

If legacy plaintext send remains supported, it must require an explicit,
separately named user action. The approved placeholder CLI flag is:

`--legacy-plaintext`

The final product name may change only through the release task, but it must stay
visibly distinct from E2E. It must not be implied by:

- missing keys,
- old clients,
- old servers,
- service discovery failure,
- route-policy fallback,
- server-side retry,
- environment variables set by a harness without a human-visible command.

Before sending with the escape hatch, the CLI/tool should show or log wording
equivalent to:

`Sending as legacy plaintext. Subject/body may be stored and visible to the service.`

Non-interactive callers must provide the explicit flag. They must not be prompted
into plaintext by default.

## Mixed-Version Matrix

| Sender | Recipient/route | Expected behavior |
| --- | --- | --- |
| v2-capable sender | v2-capable recipient + v2 route | Send `encrypted_v2`. |
| v2-capable sender | missing/stale recipient key | Fail closed; do not send plaintext unless explicit legacy flag is present and policy allows it. |
| v2-capable sender | old server or route without v2 support | Fail closed; no automatic plaintext retry. |
| old sender | v2-capable recipient | May send `legacy_plaintext_v1` only if team/service policy still allows legacy plaintext. Recipient must label it as legacy. |
| v2 server | receives v1 on E2E-required route | Reject. |
| v1 server | receives v2 envelope | Reject or return unsupported-version; must not strip ciphertext and ask for plaintext. |
| hosted server-readable MCP/dashboard | any recipient | Mode is `server_readable_hosted`, not E2E. |
| federation peer version skew | peer lacks v2 support | Fail closed for E2E route; no downgrade translation. |

## Retention and Deletion

Retention is per mode:

- `encrypted_v2`: retain ciphertext, key wraps, envelope metadata, audit rows,
  and aggregate counters per policy. Delete/redact ciphertext and wraps on
  message deletion or retention expiry. Retained audit rows must be content-free.
- `legacy_plaintext_v1`: retain under the existing legacy policy until a
  product migration says otherwise. Legacy rows must stay labeled as plaintext
  and may be purged/exported/redacted separately.
- `server_readable_hosted`: retain under hosted-account policy and label
  separately from local-client E2E.
- Customer-provided decrypted support exports are support attachments, not
  message storage. They follow support attachment retention.

Deleting or purging a legacy plaintext row may remove subject/body while leaving
content-free audit metadata. Deleting v2 ciphertext cannot require server
decryption and must not ask for private encryption keys.

## Support, Admin, Billing, and Abuse

Support/admin tooling must branch by content mode:

- For `encrypted_v2`, return metadata/ciphertext only, or a blocked response
  explaining that E2E plaintext is unavailable server-side.
- For `legacy_plaintext_v1`, content access is allowed only under the legacy
  support policy and must be labeled as server-readable.
- For `server_readable_hosted`, content access follows hosted support policy and
  must not be described as E2E.

Billing and abuse controls for `encrypted_v2` use metadata-only counters defined
in `e2e-operational-metadata.md`. Content moderation claims must not be made for
v2 E2E server-side because AC/aweb cannot inspect plaintext.

## Implementation Gates

Before E2E is broadly enabled, tests must cover:

- intended E2E send with missing recipient key fails closed with no v1 send,
- intended E2E send with stale or mismatched key assertion fails closed,
- old client/server paths reject or report unsupported version instead of
  downgrading,
- explicit legacy plaintext send requires the named escape hatch,
- legacy plaintext inbox/history rendering is labeled as legacy/server-readable,
- v2 inbox/history rendering returns encrypted metadata and ciphertext only,
- server-side search/previews operate only on legacy/server-readable content,
- support bundles and API responses do not include v2 plaintext,
- federation version skew refuses downgrade translation,
- rollback disables new E2E sends without transforming stored v2 into plaintext.

The fixture at
[`../test-vectors/e2e/legacy-plaintext-migration-v1.json`](../test-vectors/e2e/legacy-plaintext-migration-v1.json)
locks the expected mode vocabulary, display label, and no-downgrade cases for
future implementation tests.

## Review Bar

Mia should review wording and implementation readiness. Athena should be routed
any amendment that changes no-downgrade semantics, legacy escape-hatch authority,
or the content-mode taxonomy. Hestia should review rollout mechanics in
`aweb-aapv.13` before release tags.
