# Custodial Managed Encryption Contract

This document is the implementation contract for `aweb-aapv.15`. It is
subordinate to `docs/e2e-messaging-contract.md`: encrypted message v2 fields,
canonical JSON, content encryption, key-wraps, no-downgrade semantics, and
recipient binding rules remain exactly as defined there.

This contract defines how AC may participate in encrypted message v2 for hosted
custodial identities whose signing and decrypting key material is managed by
AC. It does not convert hosted custodial messaging into self-custodial E2E.

## Terminology

- **Self-custodial E2E**: the identity owner holds signing and message
  encryption private keys locally. AC/aweb receives ciphertext and metadata
  only for encrypted v2 messages.
- **Hosted custodial managed encrypted messaging**: AC holds the hosted
  identity signing private key and message encryption private key. AC can
  encrypt outbound messages for that identity and decrypt inbound messages for
  that identity. This is encrypted transport/at-rest for hosted identities, not
  self-custodial E2E.
- **Server-readable hosted boundary**: any dashboard, MCP, or hosted execution
  surface where plaintext enters AC before encryption or after decryption.

Product, docs, logs, and API copy must not call hosted custodial managed
encrypted messaging "E2E". Use "hosted managed encryption",
"custodial managed encrypted messaging", or "server-readable hosted messaging"
depending on context.

## Threat Model

### Assumptions

- AC is trusted to operate hosted custodial identities because AC holds their
  signing and message-decryption private keys.
- AC/aweb remains honest-but-curious for self-custodial identities and must not
  receive plaintext or decrypting key material for self-custodial encrypted v2.
- A compromised relay may attempt key substitution, stale-key replay, downgrade
  to plaintext, route tampering, ciphertext mutation, or use of keys from the
  wrong workspace/identity.
- A compromised hosted custodial account or AC runtime can disclose plaintext
  for that hosted identity. This is outside self-custodial E2E.
- Metadata leakage from encrypted v2 remains the accepted set in
  `docs/e2e-messaging-contract.md`.

### Defended Properties

- AC stores custodial message encryption private keys encrypted at rest under a
  dedicated KEK with purpose-bound AEAD associated data.
- AC never stores plaintext subject/body for encrypted v2 messages, including
  messages sent from or received by custodial identities.
- AC publishes custodial encryption public-key assertions signed by the hosted
  identity signing key. Team, namespace, service, or operator authority cannot
  substitute a member encryption key.
- Self-custodial senders can encrypt to custodial identities using the same
  identity-authorized key assertion model used for self-custodial recipients.
- Custodial senders encrypt to self-custodial and custodial recipients using
  the same recipient discovery and key assertion verification rules as local
  clients.

### Not Defended

- AC can decrypt messages addressed to hosted custodial identities by design.
- MCP tool input/output and dashboard compose/read for hosted custodial
  identities are server-readable by design.
- If AC loses the active or archived custodial message encryption private key,
  AC cannot decrypt messages wrapped to that key. There is no recipient-side
  recovery for already-stored encrypted v2 ciphertext without the private key.
- This contract does not add a hardware security module requirement. HSM/KMS
  backing may be added later without changing encrypted v2 envelope semantics.

## Plaintext Boundaries

Plaintext may cross the AC boundary only in these hosted custodial contexts:

- MCP tool request payloads for hosted custodial mail/chat sends.
- Dashboard compose payloads for hosted custodial sends.
- Dashboard/MCP read responses for messages decrypted for the authenticated
  hosted custodial recipient.
- Customer-provided decrypted support exports if a future support workflow
  explicitly asks the customer to export plaintext.

Plaintext must not cross AC for self-custodial encrypted v2 messages. AC must
not decrypt or request self-custodial private encryption keys.

## Key Material and Storage

AC currently stores hosted custodial signing keys in
`aweb_cloud.cloud_custodial_keys.signing_key_enc`. Do not overload that row with
message-encryption history. Custodial managed encryption uses a separate
workspace-scoped key-history table:

`aweb_cloud.cloud_custodial_encryption_keys`

| Field | Required | Description |
| --- | --- | --- |
| `workspace_id uuid` | yes | Hosted custodial workspace id. Foreign key to `aweb.workspaces(workspace_id) ON DELETE CASCADE`. |
| `encryption_key_id text` | yes | X25519 encryption key id from the E2E contract. |
| `encryption_public_key text` | yes | Raw-standard-base64-no-padding X25519 public key. |
| `encryption_private_key_enc bytea` | yes | AEAD-wrapped X25519 private key storage blob. |
| `encryption_key_assertion_json jsonb` | yes | Identity-signed public assertion JSON, including `signature`. |
| `kek_id text` | yes | Non-secret identifier of the KEK that wrapped `encryption_private_key_enc`. |
| `published_to_awid_at timestamptz` | nullable | Time this assertion was successfully published to AWID. |
| `published_to_service_at timestamptz` | nullable | Time this assertion was successfully published to service-local discovery. |
| `last_publish_error_code text` | nullable | Last safe structured publication failure code. No secrets. |
| `last_publish_error_at timestamptz` | nullable | Time of last publication failure. |
| `key_state text` | yes | One of `active`, `archived`, `disabled`. |
| `created_at timestamptz` | yes | Creation time for this key. |
| `rotated_at timestamptz` | nullable | Time this key stopped being used for new sends. |
| `archived_at timestamptz` | nullable | Time this key became decrypt-only historical material. |
| `deleted_at timestamptz` | nullable | Only set when key material is intentionally shredded. |
| `schema_version integer` | yes | Storage schema version, initially `1`. |

Required constraints and indexes:

- Primary key: `(workspace_id, encryption_key_id)`.
- Check: `key_state IN ('active', 'archived', 'disabled')`.
- Check: `schema_version = 1` for the initial implementation.
- Check: `kek_id <> ''`.
- Unique partial index: at most one non-deleted active key per workspace:
  `(workspace_id) WHERE key_state = 'active' AND deleted_at IS NULL`.
- Lookup index: `(workspace_id, key_state)` for active/archive decrypt lookup.

AC migration files must follow the AC migration conventions for that repo.

## Dedicated KEK

Custodial message encryption private keys must use a dedicated 32-byte hex KEK
and a non-secret key identifier:

`AWEB_CUSTODIAL_E2EE_KEY`

`AWEB_CUSTODIAL_E2EE_KEY_ID`

Rules:

- Production must fail closed if `AWEB_CUSTODIAL_E2EE_KEY` is missing when a
  custodial encrypt/decrypt/backfill operation needs it.
- The key must decode as exactly 32 bytes from 64 lowercase or uppercase hex
  characters.
- Production must fail closed if `AWEB_CUSTODIAL_E2EE_KEY_ID` is missing or
  empty. The id is a non-secret label such as `custodial-e2ee-2026-05`.
- Do not silently fall back to `AWEB_CUSTODY_KEY` in production.
- Tests may inject a deterministic KEK through the same environment variable.
- Any proposal to reuse `AWEB_CUSTODY_KEY` must be explicit and reviewed by
  Mia before code lands.

KEK rotation re-wraps existing `encryption_private_key_enc` rows. The rotation
operation must decrypt each row with the KEK named by row `kek_id`, re-encrypt
the same raw X25519 private key under the new KEK/id, update `kek_id`, and leave
`encryption_key_id` and `encryption_public_key` unchanged. During rotation,
read paths may accept both old and new KEK ids from an explicit configured map;
write paths use only the active `AWEB_CUSTODIAL_E2EE_KEY_ID`. A row whose
`kek_id` is not configured fails closed with `custodial_e2ee_kek_unavailable`.

## AEAD Storage Blob

The encrypted private-key storage blob is versioned binary data. Initial format:

```text
aweb-custodial-e2ee-key-v1 || 0x00 || nonce || ciphertext
```

Where:

- Prefix literal is ASCII `aweb-custodial-e2ee-key-v1`.
- `nonce` is 12 random bytes from the OS CSPRNG.
- `ciphertext` is AES-256-GCM output over the raw 32-byte X25519 private key,
  including the authentication tag.
- AAD is canonical JSON bytes of:

```json
{
  "purpose": "aweb-custodial-e2ee-private-key",
  "wrap_purpose": "custodial_private_key_storage",
  "schema_version": 1,
  "kek_id": "custodial-e2ee-2026-05",
  "workspace_id": "uuid",
  "did_key": "did:key:z...",
  "did_aw": "did:aw:...",
  "encryption_key_id": "sha256:...",
  "encryption_public_key": "base64...",
  "algorithm": "x25519"
}
```

For local-only custodial identities without a `did:aw`, omit `did_aw`; do not
encode an empty string. `did_key` is required. `workspace_id`, `did_key`,
`kek_id`, `encryption_key_id`, and `encryption_public_key` must be taken from
trusted AC workspace/agent/key state and configured KEK state, not
caller-supplied request fields.

Decrypt must recompute AAD from trusted current row state and fail if any bound
field differs. A decrypt failure is structured as key state failure, not as a
plaintext fallback trigger.

## Assertion Authority and Publication

Custodial encryption-key assertions use the same assertion payload as
`docs/e2e-messaging-contract.md`:

- `operation`: `publish_encryption_key`
- `version`: `aweb-e2ee-key-v1`
- `identity_did`: hosted identity `did:key`
- `identity_stable_id`: hosted identity `did:aw` when present; omitted for
  local-only identities
- `custody`: `hosted_custodial`
- `encryption_key_id`
- `encryption_public_key`
- `algorithm`: `x25519`
- `created_at`, `not_before`, `expires_at`
- optional `previous_encryption_key_id`
- `signature`

The signature is produced with the hosted identity signing key. AC may use its
custodial signing-key storage to produce this signature on behalf of the hosted
identity. No team controller, namespace controller, service key, API key, or
operator key may sign or replace this assertion.

`custody: "hosted_custodial"` is required for every hosted custodial assertion.
This signed field is the sender-visible trust signal that AC can decrypt for the
recipient. Discovery metadata may repeat custody, but it must not contradict the
signed assertion. Self-custodial assertions use `custody: "self"`; legacy
self-custodial assertions that predate the field may omit it as allowed by
`docs/e2e-messaging-contract.md`.

Publication surfaces:

- Global addressed custodial identities: publish to AWID identity encryption
  key discovery, so self-custodial senders outside AC can discover the key.
- Service/team-local custodial identities without public AWID address: publish
  to the service-local `agent_encryption_keys` discovery surface for the
  concrete `team_id`, `agent_id`, and `did_key`.
- BYOT pending custodial identities: do not publish or advertise encrypted
  capability until membership activation succeeds and the assertion is stored
  in the discovery surfaces needed for that team.

Publication invariant: do not mark a custodial identity encrypted-capable until
AC has durably stored the encrypted private key, verified it decrypts to the
matching public key, signed the assertion, and published it to the relevant
discovery surfaces.

## Backfill and Repair

Existing hosted custodial identities need an idempotent backfill. Backfill
applies to both global-addressed and local-only custodial identities. Local-only
backfill publishes the assertion to service-local discovery only; it must not
call AWID as a fallback.

For each active hosted custodial workspace:

1. Load trusted workspace/agent binding.
2. Require custodial signing key availability.
3. If an active encryption key exists and the assertion verifies, no-op.
4. If key material is missing, generate a new X25519 keypair.
5. Store `encryption_private_key_enc` under `AWEB_CUSTODIAL_E2EE_KEY` with the
   AEAD format above.
6. Build and sign the encryption-key assertion with the hosted identity signing
   key.
7. Publish to AWID and/or service-local discovery as appropriate.
8. Verify publication by reading back the assertion and comparing
   `encryption_key_id`, public key, identity DID, optional stable id, and
   signature.
9. Record counters and safe error codes.

Backfill must be retryable. A partial failure must not leave the identity marked
encrypted-capable unless the private key, assertion, and discovery publication
are all consistent.

Backfill failures must not cause silent plaintext sends. Hosted sends that
intend encrypted v2 fail closed with actionable guidance such as
`custodial_e2ee_key_missing`, `custodial_e2ee_assertion_unpublished`, or
`custodial_e2ee_kek_unconfigured`.

## Rotation and Archives

Rotation creates a new X25519 encryption keypair and assertion. New sends use
only the active key. Prior keys remain archived for decrypting historical
messages that contain wraps for those key ids.

Rules:

- Archive old private keys until retention policy explicitly allows shredding
  and the customer accepts that old ciphertext becomes unrecoverable for hosted
  reads.
- `previous_encryption_key_id` is set on the new assertion.
- Recipients and senders must select key wraps by `recipient_encryption_key_id`
  and identity binding, not by "latest key" alone.
- If an inbound encrypted message is wrapped to an archived custodial key, AC
  may decrypt it for the hosted recipient while marking the key as archived in
  diagnostics.
- If an archived key is missing, return a structured unrecoverable historical
  decrypt error. Do not ask the sender to resend plaintext automatically.

## Send Path Requirements

### Custodial Sender to Self-Custodial Recipient

1. Hosted MCP/dashboard receives plaintext. This boundary is server-readable.
2. AC loads the custodial sender signing key and active custodial sender
   encryption private key.
3. AC resolves recipient encryption assertions through trusted discovery:
   service-local roster/key state for local team identities, AWID for global
   addressed identities, and learned conversation metadata only where the E2E
   contract permits it.
4. AC verifies recipient assertion authority and freshness.
5. AC builds encrypted v2 with no plaintext subject/body storage, a recipient
   wrap for the self-custodial recipient, and a mandatory sender self-copy wrap
   for hosted sent history.
6. AC signs the protected envelope with the custodial sender signing key.
7. AC stores/routes ciphertext and metadata only.

### Custodial Sender to Custodial Recipient

Same as above, except the recipient assertion may be an AC-published custodial
assertion. The recipient hosted read path later decrypts using that recipient
workspace's AC-held custodial encryption private key.

### Self-Custodial Sender to Custodial Recipient

1. Local client discovers the custodial recipient assertion through AWID or
   service-local discovery.
2. Local client encrypts and signs encrypted v2 exactly as for any other
   recipient.
3. AC stores/routes ciphertext only.
4. Hosted read path selects the wrap matching the authenticated custodial
   identity's `did`, optional `stable_id`, and `encryption_key_id`, then
   decrypts with the AC-held private key.

### Custodial Replies and Continuations

AC derives recipients from trusted conversation/session metadata plus current
verified key assertions. AC must not accept arbitrary caller-supplied recipient
public keys, sender-declared policy, or envelope policy fields as authority.

Missing or stale recipient keys fail closed. The only plaintext escape hatch is
an explicit server-readable plaintext operation that is clearly labeled as not
E2E and allowed by policy.

Senders must re-resolve recipient assertions on every send. Cached assertions
from prior conversation turns must not be reused as authority for a new send. If
a recipient's signed `custody` value changes between conversation turns, the
sender must surface the trust-model change before continuing or fail closed.

Sender clients that discover a `custody: "hosted_custodial"` recipient
assertion must have enough information to tell the human that AC can decrypt for
that recipient. The exact UX is product-owned, but the trust signal is
protocol-contractual and must not be suppressed by the resolver.

### Mixed-Custody Groups

Encrypted v2 group chat uses one content key with per-recipient wraps. In a
mixed-custody group, the confidentiality floor of every new message is the least
private participant. If any recipient is hosted custodial, AC can decrypt that
message through that participant's wrap. Senders must surface this floor for
mixed-custody groups before sending or fail closed. Adding a custodial
participant affects future messages only; it does not retroactively grant AC
access to earlier ciphertext for which no custodial wrap exists.

### Recipient Resolver Matrix

Resolvers must use this table; implementations should not invent additional
fallbacks. This matrix covers paths involving hosted custodial identities.
Self-custodial to self-custodial paths are governed by
`docs/e2e-messaging-contract.md` and the `aweb-aapv.16` recipient resolver
implementation.

| Sender | Recipient | Scope | Authority source | Cache rule | Failure mode |
| --- | --- | --- | --- | --- | --- |
| custodial | self-custodial global | same or cross service | AWID identity encryption-key assertion, stable id cross-check | Re-resolve every send | Fail closed on missing/stale/mismatch. |
| custodial | self-custodial local-only | same service/team | Service-local `agent_encryption_keys` for team/agent/did_key | Re-resolve every send | Fail closed; AWID lookup forbidden. |
| custodial | hosted custodial global | same or cross service | AWID assertion with `custody: hosted_custodial` | Re-resolve every send | Fail closed on missing/stale/mismatch; surface hosted custody. |
| custodial | hosted custodial local-only | same service/team | Service-local assertion with `custody: hosted_custodial` | Re-resolve every send | Fail closed; AWID lookup forbidden. |
| self-custodial | hosted custodial global | same or cross service | AWID assertion with `custody: hosted_custodial` | Re-resolve every send | Fail closed or surface hosted custody before send. |
| self-custodial | hosted custodial local-only | same service/team | Service-local assertion with `custody: hosted_custodial` | Re-resolve every send | Fail closed or surface hosted custody; AWID lookup forbidden. |
| self-custodial | self-custodial local-only | same service/team | Existing service-local E2E discovery | Re-resolve every send, learned sender assertion only for reviewed reply continuity | Fail closed; no AWID fallback. |
| any | local-only recipient | cross service without stored route | None | Not cacheable | Unsupported; require global identity or explicit service-mediated route. |

## Read and Decrypt Path Requirements

For hosted custodial reads:

1. Authenticate as the hosted identity that owns the custodial encryption key.
   Workspace-level admin or operator authentication does not grant decrypt
   access by default.
2. Fetch encrypted v2 envelope and metadata.
3. Load active and archived custodial encryption private keys for that
   workspace.
4. Select exactly one key wrap whose `recipient_did`, optional
   `recipient_stable_id`, and `recipient_encryption_key_id` match the hosted
   identity/key. Do not reveal information about other wraps.
5. Decrypt CEK and content per `docs/e2e-messaging-contract.md`.
6. Recompute and compare `ciphertext_hash`, `ciphertext_size`,
   `key_wraps_hash`, and decrypted `inner_header_hash`.
7. Verify inner header mirrors signed outer metadata.
8. Return plaintext only to the authenticated hosted custodial read boundary.

For self-custodial reads, AC does none of this decryption.

Glass-break support/admin decryption is out of scope for v1. If implemented
later, it must use a separate authorization surface with explicit audit logging;
it must not be added as an MCP tool extension or implicit dashboard/admin power.

## Local-Only Identity Rules

Local-only identities have no AWID row and no public address. Their assertions
are still identity-authorized:

- `identity_did` is the local `did:key`.
- `identity_stable_id` is omitted.
- Address fields are omitted.
- Discovery is service/team-scoped, using trusted service state such as
  `agent_encryption_keys`, not AWID.
- AWID lookup for local-only recipients is forbidden. If service-local
  discovery has no matching row, encrypted send fails closed.

Custodial implementation must support:

- custodial to local self-custodial in the same service/team;
- local self-custodial to custodial in the same service/team;
- local self-custodial to local self-custodial through existing service-local
  E2E discovery;
- no public first-contact delivery to local-only identities outside a stored
  route or service-mediated team context.

## Failure Modes

Use structured errors. Do not log secrets or plaintext.

| Code | Meaning |
| --- | --- |
| `custodial_e2ee_kek_unconfigured` | `AWEB_CUSTODIAL_E2EE_KEY` missing for an operation that needs it. |
| `custodial_e2ee_kek_invalid` | KEK is not exactly 32 bytes from hex. |
| `custodial_e2ee_kek_unavailable` | Row is wrapped under a `kek_id` that is not configured. |
| `custodial_e2ee_signing_key_missing` | Hosted identity signing key unavailable; assertion/envelope cannot be signed. |
| `custodial_e2ee_private_key_missing` | Active or required archived encryption private key missing. |
| `custodial_e2ee_private_key_decrypt_failed` | AEAD unwrap failed or bound AAD does not match row state. |
| `custodial_e2ee_assertion_missing` | No stored identity-signed assertion for the active key. |
| `custodial_e2ee_assertion_mismatch` | Stored assertion does not match key/public identity fields. |
| `custodial_e2ee_assertion_unpublished` | Assertion not present on required discovery surface. |
| `recipient_e2ee_key_missing` | Intended recipient has no trusted encryption key. |
| `recipient_e2ee_key_stale` | Recipient key expired/not-yet-valid/mismatched. |
| `encrypted_message_not_a_recipient` | Hosted identity has no matching wrap. |
| `encrypted_message_malformed` | Envelope/ciphertext/wrap/hash/inner-header validation failed. |

## Audit and Observability

Allowed counters/log fields:

- workspace id, agent id, team id, custody mode;
- encryption key id, public key hash/key id, assertion state;
- operation name, success/failure code, duration;
- publication destination (`awid`, `service_local`) and safe status;
- message id/conversation id/session id for decrypt failures;
- key state counts for backfill and repair.

Forbidden in logs, audit rows, support bundles, metrics labels, traces, and
error details:

- raw private keys;
- AEAD-wrapped private key bytes;
- CEKs;
- HPKE shared secrets;
- decrypted subject/body/chat content;
- decrypted inner payloads or inner headers;
- full ciphertext bodies unless explicitly redacted/test-only.

Test-only assertions may inspect plaintext or key material inside isolated test
processes, but production code paths must keep redaction boundaries intact.

## Minimum Implementation Gates

Downstream implementation is not complete until tests cover:

1. Custodial key storage uses `AWEB_CUSTODIAL_E2EE_KEY`, AES-256-GCM, random
   nonce, and purpose-bound AAD; wrong AAD or wrong KEK fails.
2. Production custodial encrypt/decrypt fails closed when the KEK is missing;
   no fallback to `AWEB_CUSTODY_KEY`.
3. Backfill creates key material, signs assertion with the identity signing key,
   publishes it, verifies read-back, and is idempotent.
4. Partial backfill failure does not advertise encrypted capability.
5. Custodial sender to self-custodial recipient stores no plaintext and local
   recipient decrypts.
6. Custodial sender to custodial recipient stores no plaintext and hosted
   recipient decrypts through the managed boundary.
7. Self-custodial sender to custodial recipient stores no plaintext and hosted
   recipient decrypts.
8. Local-only recipient flows work through service-local discovery without AWID.
9. Missing/stale/mismatched recipient key fails closed and does not retry
   plaintext.
10. Non-recipient hosted custodial identity cannot decrypt and receives a
    structured not-a-recipient error.
11. Wrong key id, wrong did, wrong stable id, malformed wrap, ciphertext hash
    mismatch, key-wrap hash mismatch, and inner-header mismatch all fail closed.
12. Logs, SSE/events, dashboard list APIs, support bundles, and database dumps
    contain no known plaintext for encrypted v2 messages.
13. Rotation keeps archived keys usable for old messages and uses only the new
    active key for new sends.
14. Hosted/server-readable product copy never calls custodial managed
    encryption E2E.

## Release Boundary

Custodial managed encryption changes AC behavior and possibly aweb server/CLI
discovery behavior. Do not deploy a mixed set where one surface advertises
custodial encrypted capability before:

- key storage and backfill are live;
- assertion publication is live;
- send/read decrypt paths are live;
- dashboard/MCP copy labels hosted messaging correctly;
- rollback leaves encrypted history as ciphertext/metadata and disables new
  custodial encrypted sends rather than downgrading to plaintext.

If this contract requires changes to the encrypted v2 wire envelope,
cryptographic suite, canonicalization, no-downgrade behavior, or assertion
authority, update `docs/e2e-messaging-contract.md` first and route the change to
Athena before implementation follows.
