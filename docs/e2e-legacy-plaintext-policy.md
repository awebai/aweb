# E2E Legacy Plaintext and No-Downgrade Policy

Status: **public compatibility policy** subordinate to the
[E2E messaging contract](e2e-messaging-contract.md) and
[E2E operational metadata contract](e2e-operational-metadata.md).

E2E is an optional advanced mode. Current `aw` sends ordinary mail/chat as
server-readable plaintext by default. `--e2ee` explicitly selects encrypted v2;
once selected, failures must not silently downgrade that send to plaintext.

## Stored modes and trust boundaries

The current server stores two message content modes:

| Stored `content_mode` | Meaning | Plaintext visible to routing service? |
| --- | --- | --- |
| `legacy_plaintext_v1` | Historical or current server-readable subject/body shape. | Yes. |
| `encrypted_v2` | Version-2 ciphertext envelope; subject/body columns are empty. | No for self-custodial E2E. A hosted custody operator may decrypt through a hosted recipient wrap. |

`server_readable_hosted` is a product/trust-boundary label, not a third current
database `content_mode`. Hosted managed encryption can use an `encrypted_v2`
wire row while remaining server-readable at its custody/compose/read boundary.
Its signed assertion must say `custody: "hosted_custodial"`; it must not be
called E2E.

## Existing plaintext history

Existing plaintext cannot become E2E retroactively. It may remain readable, be
exported, or be purged/redacted under policy, but must stay labeled as legacy or
server-readable.

Recommended label:

`Legacy plaintext: this message was stored server-readable before E2E encryption.`

Server-side search and previews may operate on retained plaintext rows. They
must not derive plaintext search/previews from self-custodial `encrypted_v2`.

## No silent downgrade after E2E intent

A send with explicit E2E intent fails closed when required state is absent:

- recipient identity-signed encryption-key assertion missing, stale, expired,
  unsigned, mismatched, or unsupported;
- recipient identity/route cannot complete encrypted v2;
- server rejects `message_version=2` or the suite;
- old client/server cannot process the protected envelope;
- sender/recipient policy requires E2E and a legacy retry is suggested.

The client must not retry that message as plaintext. A service/federation peer
must not translate v2 into v1 or ask the sender to expose plaintext as recovery.

This is distinct from the current initial choice: a user who never selects
`--e2ee` is using the ordinary server-readable path, not experiencing a
cryptographic downgrade.

## Plaintext command compatibility

Current CLI surfaces:

- `--e2ee`: request encrypted v2; fail closed if it cannot complete;
- `--plaintext`: explicitly mark server-readable plaintext intent (plaintext is
  currently also the default);
- `--legacy-plaintext`: deprecated compatibility alias for `--plaintext`.

`--e2ee` and either plaintext flag are mutually exclusive. Product copy should
prefer `--plaintext` and warn that subject/body may be stored and visible to the
service. Error handling must never add that flag automatically.

## Current and rollout compatibility matrix

| Sender/route | Current or required behavior |
| --- | --- |
| `--e2ee`, valid recipient key, accepting v2 service | Send `encrypted_v2`. |
| `--e2ee`, missing/stale/mismatched recipient key | Fail before storage; no plaintext retry. |
| `--e2ee`, target rejects v2 | Fail clearly; no plaintext retry. Complete route-capability preflight is not shipped for every route. |
| ordinary current send without `--e2ee` | Send `legacy_plaintext_v1`, subject to normal delivery policy. |
| old sender to a recipient whose future policy requires E2E | A future E2E-required route must reject plaintext; this policy is a rollout requirement, not a claim that every current route enforces it. |
| hosted compose/read with operator-held decrypt key | Hosted managed/server-readable boundary, even if stored as `encrypted_v2`. |
| federation peer without v2 support | Intended E2E fails; no downgrade translation. |

## Retention and support

- `encrypted_v2`: retain ciphertext, wraps, hashes, and approved metadata;
  deletion/redaction does not require decryption.
- `legacy_plaintext_v1`: retain under plaintext policy and always label it
  server-readable.
- Hosted managed encryption: retain under hosted-custody policy and disclose
  operator decryptability.
- User-provided decrypted support exports are separate support attachments, not
  message storage.

Support/admin tooling branches by stored mode and custody boundary. For
self-custodial encrypted v2 it returns metadata/ciphertext or a blocked response;
for plaintext it may return content under plaintext policy; for hosted custody
it follows the disclosed hosted boundary.

## Conformance fixtures

[`../test-vectors/e2e/legacy-plaintext-migration-v1.json`](../test-vectors/e2e/legacy-plaintext-migration-v1.json)
pins the two stored modes, hosted boundary label, current/deprecated CLI flags,
read shapes, and no-downgrade cases.

[`../test-vectors/e2e/mixed-version-rollout-v1.json`](../test-vectors/e2e/mixed-version-rollout-v1.json)
is explicitly a **rollout requirements matrix**, not a current capability
inventory. Its consumer verifies completeness, no-fallback posture, flag naming,
and links to the retained contracts.
