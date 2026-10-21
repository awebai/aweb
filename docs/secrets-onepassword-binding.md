# 1Password binding and credential versions

The owner's 1Password vault is the value-ingress and rotation path. Secrets
stores an immutable reference and a natively sealed service-account token,
never a copy of the referenced item value. This extends [the custody design](design/secrets.md#53-1password-backend)
without changing `secret/1`, `SealContext` or the use-approval version format.

This schema slice adds the two `change/1` projections below. Both remain outside
`ChangeSets.APPLICABLE_KINDS` until scoped persistence, staged-row checks and
atomic confirmation are implemented. Parsing or hashing a projection supplies
no backend authority.

## Console-only change projections

Both kinds have only `op: "create"`: each creates an immutable next version,
including when replacing an existing active version. Their exact `after`
fields are covered by B2's existing canonical approval bytes. Unknown fields,
including values and plaintext fingerprints, refuse. A team-auth drafter
cannot submit either kind. The envelope binds installation, team, installation
generation and configuration revision.

`backend_credential/1` has item `ref: "onepassword"` and:

```json
{"v":1,"backend":"onepassword","credential_id":"bkc_onepassword","version":3}
```

`version` names the inert native-sealed token version brought by the console.
The reserved `bkc_onepassword` custody context is outside the ordinary `sec_`
namespace. There is one per installation/team; it must never become an ordinary
secret record, grant target, operation, job credential or tool-list entry.
Ingress reuses native envelope sealing and its installation/team/id/version
context. The token is encoded through the bearer codec. Its allocator survives
cancellation, destruction and replacement; it is never reset. Neither a staged
version nor a cancelled draft changes the active credential.

`onepassword_binding/1` has item `ref` equal to its `secret_id` and:

```json
{
  "v":1,
  "secret_id":"sec_19ab42",
  "version":4,
  "credential_version":3,
  "vault_id":"aaaaaaaaaaaaaaaaaaaaaaaaaa",
  "item_id":"bbbbbbbbbbbbbbbbbbbbbbbbbb",
  "fields":{"value":"credential"},
  "item_version":7
}
```

All versions are positive integers, excluding booleans. `version` is the
monotonic local secret version; `item_version` is the version from the same SDK
read as the validated fields. Rebinding another item whose remote version also
happens to be 7 still creates a different local version. `credential_version`
pins the exact native-sealed service-account version used for the observation.
Vault and item IDs are 26 lowercase alphanumeric characters. Field selectors
are exact field IDs of 1–128 ASCII letters, digits, underscores or hyphens;
mutable titles and first-match selection are not supported.

`fields` names one complete structured-value family from the sole shared
required/optional field table: `value`; `username` and `password`; `client_id`
and `client_secret`; or `access_key_id` and `secret_access_key`, with optional
`session_token`. That syntax check does not infer a secret kind. Staging,
draft and confirmation must validate against the actual record's kind and
immutable placement parameters. The SDK read must validate the selected whole
mapping through the shared custody codec. A selected optional field must exist
and be valid; missing never means an empty substitute.

A preceding `secret/create` in the same change may provide an inert initial
parent with backend `onepassword`. An existing parent must belong to the exact
envelope scope and use that backend. Draft and confirmation must compare the
full projection, immutable shape, scope and versions to the server-staged row.
A caller-supplied item version is not a verified SDK observation. Confirmation
uses the single existing passkey-approved change path and revision claim.

## Use-time opener API

`aweb_secrets.custody.opening.UseSecretOpener(db, native=...,
credential_opener=...)` is the common native/1Password read seam. Composition
passes `custody.opener` and the active-only `custody.backend_credential_opener`;
it never passes `backend_credential_preview`. The latter remains exclusively
in the owner-console service for inert previews. Backend selection comes from
the scoped, active secret record, never an input supplied by the requesting
agent. The common opener is read-only and does not activate either new kind.

Before S3, `await opener.observe(context)` returns an immutable, value-free
`BackendObservation` for 1Password, or `None` for native custody. The binding
includes the exact local context, pinned active credential context, immutable
reference and shape, opaque version handle and stored item version. Observation
adds the remotely validated item version and update time, retaining no value.
The SDK accepts only the token/context pair returned by the dedicated opener.

After separate reconciliation, S13 binds that observation into
`await opener.check_observation(tx, context, observation)` under its held
authority. The checker takes no new row locks and performs no network I/O or
writes. A changed remote version raises `SecretVersionChanged`; a missing,
disabled, destroyed, foreign or superseded binding/token refuses. Neither
result activates a version. Native custody requires `observation is None`.

After dispatching commits, `await opener.open(context)` returns the existing
redacting `Plaintext`. For 1Password it reads the item afresh, requires the exact
authorized item version, then rechecks the local binding/credential epoch
before returning. There is no native fallback or value cache. Successful real
vault reads and phase-correct S13 composition are separate release proofs.

## Token replacement and dependencies

Activating another service-account version never silently substitutes it under
old reference contexts. Preparation discovers the affected reference roots
without child locks and holds the common installation fence, roles, ancestry,
grants and complete sorted B2 union, including the confirming approval, before
any approval consumption or consequence callback. Record and custody writes
follow that authority phase, parent before custody.

The confirmed transaction invalidates old dependent contexts and use approvals,
disables descendants, and deletes the old token ciphertext. References
explicitly rebound to the new credential in that same change may activate
atomically; the others have no usable active version until an owner confirms a
new binding. A stale pending draft naming the former credential refuses.
Existing disabled flags stay disabled, including descendants. The console
preview discloses affected references and registration/use consequences.

All activation, invalidation, ciphertext destruction, required audit enqueue
and revision changes commit together or roll back together. A returned sorted,
scoped affected-ID set drives cache eviction only after commit. Active-version,
credential-epoch and disabled-state checks are the controls; destroying a blob
or evicting a cache cannot replace them.

## Remote version observation: decision 92

Coordinator decision 92, receipt
`2f7026a2-6a1b-4f98-b19e-fc834dea13d8` (2026-10-21), permits a valid changed
value under the same immutable reference to activate for **later fresh
admissions without another owner passkey**. The grant binds the reference:
the owner's vault is the approved ingress and rotation path. Changing the
value does not change who may use it, its destinations, or its operations.
The ruling's conditions are:

- The observed whole value must fit the immutable kind and placement shape.
  Invalid shapes activate nothing and refuse with a fixed value-free cause.
- A deleted or unresolved item activates nothing and refuses. Failed reads
  must alert through phase-appropriate audit and console status.
- Activation allocates a new monotonic local version under complete forest,
  grant and B2 prelocks, with old-version approval invalidation and replacement
  consequences. Cache authority changes with the version.
- This attempt and all old version-bound approvals refuse. A later admission
  evaluates its own policy and gets a fresh approval wherever `approve_only`
  or per-use approval requires one.
- This is a value-version change, not authority widening. The shared hooks
  owner defines its reviewed event mapping; no producer-local action is used.

`opener.observe(context)` performs the SDK read **outside every held DB
transaction and lock**. Its immutable, value-free observation binds full
scope, local version, exact reference and credential epoch, remote item version,
and successful whole-value/immutable-shape validation. It is internal
observation data, not a wire format or another authority/planner type. An
unvalidated or unresolved observation cannot be promoted.

A separate scoped, fenced transaction before S3 prepares the complete
forest/grant/B2 union, then compares those epochs against current state.
A stale observation cannot change a newer binding. A successful CAS records
and activates the new local version, invalidates old approvals/descendants,
and enqueues its required observation event in that same transaction. It
refuses this attempt; S3 must start any subsequent attempt from fresh authority.
No SDK I/O runs under these locks.

For audit, `resource_ref` is the opaque minted `secret_id`, never a display or
provider reference. Each local reference version retains its own random
`sv_<UUID-hex>` handle for `before_ref`/`after_ref`. These handles never encode
provider item IDs, provider version numbers, plaintext or fingerprints. A stale
or failed CAS emits no successful observation event. Invalid shape or failed
lookup has no newly activated version or successful `after_ref`.

The final S3 `check_observation(tx, context, observation)` performs DB-only
comparisons under authority already held, followed by the final installation
and live-time checks. It cannot allocate versions, acquire late B2 locks,
revoke approvals, or enqueue observation consequences. After `dispatching`
commits, `opener.open(exact_context)` rereads before any upstream byte or runner
release. A late mismatch or read failure closes the original attempt through
S3 as `not_sent`; it never transplants a new version into that admitted intent.
Any remote-version reconciliation then runs separately with complete prelocks.

Phase-correct audit matters: pre-S3 failures produce a refused use event.
Post-commit/pre-release failures produce `not_sent`, with their cause retained
in console/operational state. The current hook catalog forbids `refusal_code`
on `not_sent`; producers must not attach that field or fabricate a pre-S3
refusal. The shared observation act/authority and invalid-value refusal-code
delta remain with hooks-design until reviewed; this schema slice emits none.

Required local outbox storage and the transition share one transaction. A
failed outbox insert rolls both back and the use still fails closed without
release. Audit target or delivery unavailability is a different condition and
never delays old-authority containment. There is no value/client cache or
fallback to native values.
