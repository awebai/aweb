# aw-hooks: catalog, bindings and delivery

Status: **specified experimental public contract, not yet shipped**. Owner: the
aweb OSS hooks lane (aweb-acgh.16). This document is the source of truth for the
`aweb.hooks` catalog, version 1, for owner-activated hook bindings, and for how
a producer signs and delivers hook events. Its machine-readable authority is
four vectors:

- `docs/vectors/hook-catalog-v1.json`: the hooks, their payload allowlists and
  rules, with positive and negative cases;
- `docs/vectors/hook-binding-cases-v1.json`: binding states, activation, the
  `active_from` pad and revocation, as replayable cases;
- `docs/vectors/hook-event-envelope-v1.json`: the signed event envelope;
- `docs/vectors/hook-delivery-credential-v1.json`: the request credential that
  carries an event to a target.

The strict catalog reader is `aweb_naapp.hooks.catalog`
(`naapp-lib/src/aweb_naapp/hooks/catalog.py`). The envelope and credential
authority is the Go package `cli/go/hookevent`, which regenerates both of
their vectors byte for byte. The Python reading is `aweb_naapp.hooks.envelope`
and `aweb_naapp.hooks.delivery`, behind the dependency-light `hooks` extra, and
passes the same vectors with the same refusal codes. The design and its rationale are
in [the audit substrate design](design/audit-substrate.md).

This contract adds named, owner-activated extension points beside the
in-process [`on_mutation` seam](aw-hooks-sot.md), which is unchanged. They do
not replace each other. `on_mutation` is post-commit and best effort, so it
never carries a hook event.

## What a hook is

A hook is a named, versioned point at which an effect is recorded. An installed
app registers one of its hook-only tools as a hook's target, and the team owner
activates that registration. From then on, the layer that **effects** an action
fires the hook for it:

- the core server fires for the core coordination state it changes;
- a naapp server fires for its own state and its brokered external calls;
- `aw` fires only for purely local effects, which reach no server.

Each effect produces exactly one logical event, with one `event_id`. The event
is delivered at least once to every target owed it. A layer that only requests
an action never fires for it.

Server-fired hooks are the audit guarantee, because the agent cannot route
around them. Client-fired hooks are cooperative. A patched `aw`, a direct HTTP
call or a deleted local outbox skips them, so consumers record and show them as
agent-reported, never as mediated fact.

## The catalog, `aweb.hooks` version 1

| Hook | Class | Producer | Audit-critical | Fires for |
| --- | --- | --- | --- | --- |
| `post-secret-use-hook` | server | an app with an active production | always | Every brokered use of a secret: refusal, approval request and decision, admission, the durable dispatch intent, the result, and an unknown outcome and its reconciliation. |
| `post-governance-hook` | server | an app with an active production | widening acts only | App-side governance: roles, credentials, grants, resources, policy, runners and the installation-wide switch. The catalog fixes each act as widening or narrowing. |
| `post-manifest-command-hook` | server | an app with an active production, for its own tools | never | Every admitted mutation tool call and every attributable refusal. Reads fire only for tools the production lists in `reads`. |
| `post-mutation-hook` | server | the core server | never | The core mutations listed under [`post-mutation-hook`](#post-mutation-hook). |
| `post-command-hook` | client | `aw`, signed by the member | never | The local effects of an `aw` command (see [`post-command-hook`](#post-command-hook)). |

**One effect, one hook.** A more specific hook takes its effects away from the
generic one. A tool call whose effect is a secret use fires only
`post-secret-use-hook`, and one whose effect is a governance act fires only
`post-governance-hook`. Neither also fires `post-manifest-command-hook`. The
catalog records this in `precedence`.

**Versioning.** A binding names `(catalog id, catalog version, hook)`. Any change
to a payload, an addition included, is a new catalog version. A binding that
names an unknown catalog id, version or hook cannot be activated, and a consumer
refuses its events. Blocking `pre-*` hooks do not exist in version 1.

## Payloads

Every hook's payload is a **flat allowlist**:

- a JSON object whose values are strings, integers, booleans or lists of
  strings, with no nested objects, floats or nulls;
- each field has a type with a pattern and bounds, or an enum; a list has
  bounds and unique items;
- an unknown field is refused, so a producer cannot leak data through an extra
  field;
- conditional rules say which fields an event of a given kind needs or must not
  carry.

Values are references, identifiers, enums, digests and bounded integers. A
payload never carries a secret value, a message body, a subject, a preview, a
task title or comment text, or any other free text. A `ref` is an opaque typed
identifier such as `task:<uuid>`: at most 128 characters, with no spaces, `@`,
`+` or `=`, so it cannot carry an email address or a padded base64 token.

**Digest rule.** No payload digest is ever unsalted over bytes that contain, or
may echo, a credential. For `post-secret-use-hook`, `request_sha256` and
`params_sha256` cover the request **before** credential injection. For
`post-manifest-command-hook`, the historical field name `request_sha256`
means a producer-keyed HMAC-SHA-256, as specified below: even an uninjected
generic tool request may contain a credential. Response bytes are committed
only through a producer-keyed HMAC (`upstream_response_hmac`, `returned_hmac`).
See [audit-substrate §A2](design/audit-substrate.md#a2-the-catalog-v1),
"Manifest request commitment".

**Check order.** A consumer checks an event's payload in this order and reports
the first fault:

1. the hook is known (`unknown_hook`);
2. for `post-mutation-hook`, the `mutation_type` value (`missing_field`,
   `invalid_value`);
3. unknown fields (`unknown_field`);
4. missing required fields (`missing_field`);
5. each value against its type, bounds and constants, in field-name order
   (`invalid_value`);
6. the rules, in their listed order (`rule_violation`);
7. a governance act's catalog direction (`direction_mismatch`), or a command
   class's local effects (`rule_violation`).

The catalog vector gives the exact fields. The sections below give their
meaning.

### `post-secret-use-hook`

`action` is one of `refused`, `approval_requested`, `approval_decided`,
`admitted`, `dispatching`, `completed`, `not_sent`, `outcome_unknown` and
`reconciled`. `dispatching` is the durable intent, committed before any byte of
the external call is sent. `op_kind` is `broker` or `run_job`.

- A broker call names its target by method, host, port and path template, plus
  `operation_id` and `operation_digest` for a named operation.
  `target_path_template` is the owner-configured destination or operation
  template, such as `/v1/charges/{id}` or `/v1/charges/**`, and never the
  request's concrete path or query: a concrete path can carry a credential, as
  in `/bot<id>:<token>/sendMessage`. The type refuses `@`, `%` and paths over
  256 characters, but only the producer can guarantee a template, so producers
  test that a request whose concrete path holds a credential-shaped segment
  emits only its configured template. A runner job names `runner_id`, `job_id` and
  `job_digest` instead, and the two sets exclude each other.
- `refused` requires `refusal_code`, from the catalog's 30 codes; no other
  action carries one.
- `completed` requires `disposition` (`returned`, `withheld` or
  `stored_as_secret`) and `undeclared_credential`. A returned result carries
  `returned_hmac`, a withheld one never does, and a stored one names
  `derived_secret_id`. An undeclared credential in the response forces
  `withheld`.
- `approval_decided` requires `approval_id` and `approval_decision`.

A withheld value and an undeclared credential are properties of the `completed`
event, not separate events.

### `post-governance-hook`

`act`, `direction` and `authority` are required. The catalog fixes each act's
direction, and a consumer refuses an event whose `direction` differs:

| Widening | Narrowing |
| --- | --- |
| `role.designated`, `credential.enrolled`, `credential.recovered`, `grant.created`, `grant.changed`, `resource.created`, `resource.version_added`, `resource.enabled`, `policy.changed`, `runner.registered`, `installation.enabled` | `role.revoked`, `credential.revoked`, `grant.revoked`, `resource.disabled`, `resource.replaced`, `runner.deregistered`, `installation.disabled` |

`grant.changed` is widening whatever the change, so a change that only narrows
a grant is still gated. A producer that must contain without waiting uses
`grant.revoked`. `resource.replaced` is narrowing: replacing a compromised value
is containment and must not wait on audit availability. It still takes the
strongest authority: `owner_act` or `passkey_session`, never `team_cert`.

`authority` is how the act was authorized:

- `owner_act` requires `owner_act_sha256`;
- `passkey_session` requires `approval_evidence_sha256`;
- `team_cert` is allowed only for a narrowing act, and never for
  `resource.replaced`.

### `post-manifest-command-hook`

`app_id`, `tool`, `operation_kind` (`mutation`, `read` or `refusal`),
`request_sha256` and `http_status` are required. For this hook,
`request_sha256` is a producer-keyed HMAC-SHA-256 commitment, encoded as 64
lowercase hexadecimal characters. The historical name is retained; a plain
SHA-256 is never emitted here. Surface-only secret ingress does not prove
that a generic tool's parameters contain no credentials.

The producer computes:

```text
request_sha256 = hex_lower(HMAC-SHA-256(K,
    "aweb.post-manifest-command.request/1\n" || canonical(context) || "\n" ||
    canonical_request_bytes))
```

`context` contains exactly `app_id`, `team_id`, `installation_id`, `generation`
and `tool`, from the admitted installation and matched manifest tool, encoded
with the envelope's canonical JSON rules. `canonical_request_bytes` are the
canonical request bytes of that tool's manifest mapping, before credential
injection. Only the commitment leaves the producer; parameter values and
concrete paths or queries are never copied into event fields.

`K` is an independent, randomly generated 32-byte producer-local secret,
persisted in the producer's private configuration. It is never a signing seed,
a public key, a team key or a manifest field, and is never sent to a target.
The runtime loads it through the shared key-file reader as 64 hexadecimal
characters, with one trailing newline allowed. A runtime configured to produce
this hook fails startup if the key is absent or malformed. All
replicas of that producer use the same key. Rotation changes subsequent
commitments; retries deliver the already-signed outbox bytes without
recomputing them. Cross-key comparisons have no meaning.

The target verifies the event's signature and the commitment's shape. It
cannot recompute this HMAC and does not obtain proof of the request's contents;
the commitment is the authenticated producer's statement. A refusal carries
no `result_ref`.

### `post-mutation-hook`

Every event has `mutation_type` and `target_ref`, and optional `before_ref` and
`after_ref`. Each mutation type adds its own fields:

| `mutation_type` | Its own fields |
| --- | --- |
| `task.created` | `task_ref`, `status`, `task_type`, `priority`; optional `assignee_alias`, `parent_ref` |
| `task.updated` | `task_ref`, `changes` (the names of the changed fields, never their text); optional old and new `status`, assignee alias and `priority`, each in pairs |
| `task.deleted` | `task_ref` |
| `task.comment_added` | `task_ref`, `comment_ref` |
| `task.dependency_changed` | `task_ref`, `change` (`added` or `removed`), `depends_on_ref` |
| `task.answered` | `task_ref`, `answer_ref` |
| `mail.sent` | `conversation_ref`, `recipient_refs`, `priority`, `content_mode`, `federated`; optional `attachment_count` |
| `mail.acknowledged` | optional `conversation_ref`, `sender_ref` |
| `chat.message_sent` | `session_ref`, `recipient_refs`, `content_mode`, `federated` |
| `identity_grant.minted` | `grant_did_key`, `scopes`, `expires_at`; optional `subject_did_aw`, `issued_by_certificate_id` |
| `identity_grant.revoked` | `grant_did_key` |
| `app.installed` | `app_id`, `origin`, `digest`, `scopes`; optional `installation_id`, `generation` |
| `app.updated` | as `app.installed`, plus `previous_digest` |
| `hook_binding.activated` | the binding's identity (`binding_id`, `kind`, `app_id`, `installation_id`, `generation`, `catalog_id`, `catalog_version`, `hook`), `active_from`, `owner_act_sha256` |
| `hook_binding.revoked` | the binding's identity, `reason` (`owner_act`, `uninstalled` or `superseded`); `owner_act_sha256` when an owner revoked it; optional `cancelled_count` with the cancelled `seq` range |
| `app_key.revoked` | `app_id`, `kid`, `purposes` |
| `membership.connected` | `member_alias`, `member_did_key`; optional `member_did_aw`, `workspace_ref` |
| `membership.workspace_retired` | `member_alias`, `workspace_ref` |
| `membership.certificate_issued`, `membership.certificate_revoked` | `certificate_id`, `certificate_sha256`, `member_did_key`, `member_alias`, `registry_origin`, `registry_recorded_at`, `observed: true`; optional `member_did_aw` |

App `scopes` use the app registry's scope pattern, such as `folio:write`;
identity-grant `scopes` are grant scope tokens, such as `mail.send`.
`task.answered` fires once the conditional task answer exists in core.
`membership.certificate_*` events are registry facts that core **observes** at
the team's registry; it does not effect them. They carry the registry's own
timestamp and `observed: true`. Reservations and agent status reports are not
core mutations for this hook: they are operational locks and health signals.
The catalog lists them under `excluded_core_events`.

### `post-command-hook`

`command` is the canonical command path, such as `aw id rotate-key`. `flags`
lists flag names only, never values. `exit_status` is the command's exit status.
`command_class` names one class, and `local_effects` lists effects of that class
only:

| `command_class` | `local_effects` |
| --- | --- |
| `identity_key` | `identity_key_created`, `identity_key_rotated` |
| `team_certificate` | `team_certificate_stored`, `team_certificate_removed` |
| `app_approval` | `app_approval_recorded`, `app_approval_revoked` |
| `grant_snapshot` | `grant_snapshot_stored`, `grant_snapshot_removed` |

A command with both local and server effects produces one client event for its
local effects, and the server produces one event per server effect. The two
share the command's `trace_id` and are not duplicates. Reads fire nothing.

## Bindings

An app declares hook bindings in its manifest v2 `hooks` slot:
`registrations` bind one of its tools, declared with
`invocation_contexts: ["hook"]`, as a target; `productions` name the hooks it may
emit, with optional `reads`. Version 2 of the manifest is defined by D1's manifest
contract. A binding is a child of the team's install record, keyed by the
installation and its generation.

| State | Meaning |
| --- | --- |
| `pending` | Declared by the installed bytes, not yet activated. Nothing is delivered to it, and its producer's events are refused. |
| `active` | Activated by the owner. Owed events from its `active_from` on. |
| `revoked` | Revoked by the owner or by uninstall. Terminal. |
| `superseded` | Replaced by a new generation of the install. Terminal. |

- **Install never activates.** An install or update by an admin creates its
  bindings as `pending`.
- **Only the team owner activates or revokes**, with an `aweb.owner-act/1`
  signed by the team's current controller key ([owner act](owner-act.md)). An
  act signed by any other key, an admin's or a rotated-out team key, is refused
  with `owner_required`. The verifier proves the key, not the person holding
  it; signing only for the organization owner after a fresh step-up is the
  signing deployment's obligation. Activation
  compares the act's subject, including the manifest digest the owner's client
  fetched, with the stored pending row.
- **A new generation supersedes.** Every binding of the old generation becomes
  `superseded`, and the new generation's bindings start `pending`. Activation is
  never inherited, however similar the new bytes are.
- **Unknown catalogs stay pending.** Activating a binding whose catalog id,
  version or hook is unknown is refused with `unknown_catalog`.
- **The `active_from` pad.** Activation sets `active_from` to the activation
  time plus 60 seconds, which is the resolution freshness bound. Every producer
  has refreshed by then. An event is owed to an `active` registration only when
  `active_from` is at or before the event's `occurred_at`, so a new target is
  never fed history.

**Revocation** is the exfiltration remedy:

1. the revoked target receives `hook_binding.revoked` as its final entry,
   whatever hook it was registered for, so its record ends with an explanation;
2. its other undelivered events are cancelled;
3. every other `post-mutation-hook` registration owed that event receives it
   with the cancelled count and `seq` range, so its `verify` explains the gap.

Producers stop delivering within the freshness bound, so the revoked target may
receive redacted activity for up to 60 seconds after revocation. Owner-facing
copy says so. Uninstall revokes every binding of the installation the same way.

**Switching targets** follows a fixed order: activate the new target, wait for
its `active_from`, then revoke the old one. Audit-critical effects then always
have a target.

## Delivery

**Outbox.** A producer writes the event to its own durable outbox **in the same
transaction as the effect**. If the event cannot be written, the effect does not
commit. `event_id` is minted once there, as a random UUID with no derivation,
and a retry never mints another. `producer.seq` counts events per producer,
team and hook, without gaps, in the same transaction.

**Materialization.** A producer turns an event into deliveries when it drains
the outbox, from a view of the team's registrations no older than 60 seconds:
one delivery per registration owed the event. A stale view leaves the event
pending, and it is never dropped. Every target receives byte-identical signed
bytes.

**Transport.** Each delivery is an HTTPS `POST` to the binding's origin and
path, authenticated by the `hook-delivery` credential, which binds the request
to that binding and event (see [The delivery credential](#the-delivery-credential)).
Egress takes
the destination only from the activated binding. It uses HTTPS only and follows
no redirects. Private and internal destinations are refused unless a
self-hosted operator allows them; a hosted deployment always refuses them.

**Acknowledgement.** A target answers:

| Response | Producer's outcome |
| --- | --- |
| 2xx with `{event_id, disposition: "appended" \| "duplicate", receipt?}` | `delivered` or `duplicate`. The producer keeps the receipt, and at least the highest receipt per team and binding. |
| `409 event_conflict` (same id, different bytes) | `conflict`: never retried, surfaced as a fault. |
| A schema or authorization refusal | Retried with bounded backoff, in case a registry view is stale, then `rejected` and surfaced. |
| A network error or 5xx | Retried with capped exponential backoff and never dropped. After the operator's disclosed delivery horizon it is `stalled` and surfaced to the owner. |
| The binding is no longer active when the producer sends | `cancelled`, with its reason. |

Delivery is at least once. Consumers deduplicate on `(team_id, event_id)`.

## The audit-critical gate

For an audit-critical event (every `post-secret-use-hook` event, and widening
`post-governance-hook` acts), the producer refuses the effect, with
`audit_target_unavailable` and the real error logged, unless:

- a registration view no older than 60 seconds holds an `active` registration
  for the hook whose `active_from` is at or before the event's `occurred_at`;
  and
- the event row commits before any external dispatch.

A registration still inside its pad does not count. Narrowing acts are enqueued
in their own transaction and never refused by this gate, because containment
must not wait. Revocation can still race the drain, so an audit-critical event
whose deliveries all end `cancelled` or `rejected` is a **surfaced fault**: the
owner learns that an effect happened with no surviving audit record.

`post-mutation-hook` is not audit-critical. Core enqueues it in the mutation's
transaction whenever its fresh view shows an active registration, and never
refuses a mutation for want of one.

## Event envelope

Every event is one envelope, signed by its producer:

```json
{
  "v": 1,
  "type": "aweb.hook-event",
  "catalog": {"id": "aweb.hooks", "version": 1},
  "hook": "post-mutation-hook",
  "event_id": "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
  "trace": {"id": "4bf92f3577b34da6a3ce929d0e0e4736", "origin": "signed_request"},
  "team_id": "demo:example.com",
  "producer": {"kind": "core", "origin": "https://aweb.example.com", "kid": "hook-2026-10", "did_key": "did:key:z6Mk...", "seq": 812},
  "actor": {"did_key": "did:key:z6Mk...", "certificate_id": "c_41", "alias": "bond", "authority_mode": "team_cert", "attestations": []},
  "occurred_at": "2026-10-20T12:00:00.412Z",
  "fired_at": "2026-10-20T12:00:00.415Z",
  "result_status": "success",
  "payload": {"mutation_type": "task.updated", "target_ref": "task:...", "task_ref": "demo-aa1", "changes": ["status"], "old_status": "open", "new_status": "in_progress"}
}
```

**Signing bytes** are the ASCII prefix `aweb.hook-event/1` and a newline,
followed by the envelope's canonical JSON. Canonical JSON here means:

- object keys sorted, with no insignificant whitespace;
- every string is printable ASCII (0x20 to 0x7E), and only `"` and `\` are
  escaped;
- integers lie within plus or minus 2^53 - 1;
- there are no floats and no `null`: an absent value is an absent field;
- objects and arrays nest at most eight deep. The bytes are parsed before any
  signature is checked, so deeper input is refused before it is read.

A verifier re-encodes what it parsed and requires identical bytes, so every
language produces and accepts the same bytes. The signature is a detached
Ed25519 signature by the producer's `did:key`, written exactly one way: 86
characters of the standard base64 alphabet, with no padding and zero trailing
bits. Every other spelling of the same bytes is refused (`signature_encoding`).

**ASCII by construction.** Every catalog payload type is an identifier, an
enum, a digest, a bounded integer or a pattern-bounded ASCII string, and every
envelope field is an identifier or a timestamp. A producer fills payloads from
its own identifiers and never from user text, so an ASCII-only envelope never
makes an effect unsignable. On `post-command-hook`, `command` is the command's
path in `aw`'s own command tree and `flags` are the parser's declared flag
names; argument values never enter the event. If `aw` cannot express an event
in these types, it records nothing for that command, and the command itself
still runs: client events are cooperative and never block the command they
describe.

**Fields:**

- `event_id` is minted once, in the effecting transaction (see
  [Delivery](#delivery)).
- `trace.id` is a W3C trace id (32 lowercase hex characters, not all zero), and
  `trace.origin` is `signed_request` when the producer took it from a signed
  request, or `producer` when the producer minted it. A trace correlates; it is
  never authority and never a deduplication key.
- `producer` depends on its kind:
  - `core`: `origin`, `kid`, `did_key`, `seq`;
  - `app`: `origin`, `app_id`, `installation_id`, `generation`, `kid`,
    `did_key`, `seq`;
  - `client`: `did_key` and `certificate_id`, with no `seq`, because a client's
    events are bypassable and their gaps prove nothing.

  `seq` counts the producer's events per team and hook, without gaps, from 1.
- `actor` always carries `authority_mode` (`team_cert`, `identity_grant`,
  `app_key`, `link_capability`, `owner_act` or `system`) and `attestations`.
  - Every authority but `system` names the actor's `did_key`, and may add
    `did_aw`, `certificate_id` and `alias`. A `system` actor carries no
    identity.
  - `grant_id` is present exactly when the authority is `identity_grant`.
  - `attestations` holds at most four strict unpadded base64url strings. Each
    is the signed bytes of an attestation. They are untyped at this layer: a
    consumer verifies each one under its own contract before it relies on it,
    and custody and principal facts appear only there.
- Every `did_key` is an Ed25519 `did:key`.
- `occurred_at` is when the effect happened and `fired_at` when the event was
  built: UTC with exactly three fractional digits, in their one canonical
  spelling, with `fired_at` never earlier.
- `result_status` is `success`, `denied`, `failed` or `outcome_unknown`.
- `payload` is the catalog payload for the hook.

**Verification** requires the team the verifier expects; without one it
refuses (`verifier_misconfigured`). It then checks, in this order, and reports
the first fault:

1. the prefix (`wrong_prefix`);
2. a strict parse (`duplicate_key`, `float_value`, `null_value`,
   `string_not_ascii`, `too_deep`, `invalid_json`);
3. canonical bytes (`not_canonical`);
4. the envelope's fields, top down (`unknown_field`, `missing_field`,
   `invalid_value`), with the catalog (`unknown_catalog`) and the hook
   (`unknown_hook`);
5. a flat payload of strings, integers, booleans and lists of strings
   (`invalid_value`);
6. a producer kind the hook allows (`producer_not_allowed`), so a member can
   never sign a server hook;
7. for a client event, an actor equal to its signer (`actor_not_signer`), so
   one member cannot file events as another;
8. the team the verifier expects (`team_mismatch`);
9. the signature's spelling (`signature_encoding`), then the signature
   (`bad_signature`).

The catalog reader then checks the payload against its hook's allowlist (see
[Payloads](#payloads)).

**What verification proves.** A verified envelope is well formed, belongs to
the expected team, and was signed by the key it names as its producer. That is
self-consistency, not authority. Authority comes from elsewhere:

- A server producer signs with a key whose declared purposes include
  `hook-event`: an app's v2 `app_keys` entry, or the core server's hook key. A
  consumer resolves both through the team's server (aweb-acgh.7), requires an
  active production for the hook, and records the key it verified against at
  ingest.
- A client signs with its member key, and its delivery carries the member's
  team certificate (see below), signed by the team's current key and naming
  that key and certificate id. The target checks the certificate's revocation
  status with the shared team-auth verifier.

## The delivery credential

A delivery is an HTTPS `POST` of the canonical JSON body
`{"hook_event": <strict unpadded base64url signing bytes>, "signature": <envelope signature>}`
with these headers:

- `Authorization: AWEB-Hook DIDKey <did:key> <signature>`, the signature over
  the signed payload, spelled as event signatures are (86 standard base64
  characters, no padding, zero trailing bits);
- `X-AWEB-Signed-Payload`, the canonical signed payload, in strict unpadded
  base64url;
- for a client producer only, `X-AWID-Team-Certificate`, the member's team
  certificate, encoded as team-auth encodes it. A server producer sends none.

The signed payload is:

```json
{
  "v": 1,
  "auth": "hook-delivery",
  "aud": "https://logs.example.com",
  "method": "POST",
  "path": "/hooks/ingest",
  "body_sha256": "<hex SHA-256 of the body>",
  "team_id": "demo:example.com",
  "binding_id": "6f9619ff-8b86-4011-b42d-00c04fc964ff",
  "event_id": "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
  "producer": "core",
  "kid": "hook-2026-10",
  "did_key": "did:key:z6Mk...",
  "timestamp": "2026-10-20T12:00:01Z"
}
```

- `aud` is the target's origin and `path` its raw path and query.
- `team_id` is a non-empty team id, and `timestamp` is UTC to the second in its
  one canonical spelling.
- `producer` is `core`, `app:<app_id>` or `client:<certificate_id>`.
- `kid` is the server producer's key id, or `member` for a client.
- The credential's purpose, `hook-delivery`, is separate from the event's
  content signature, from `app-event` and from `hook-resolve`, so none of them
  can be replayed as another.

The target holds facts of its own: its public origin, the binding the delivery
must name, the team's current controller key (read fresh from the team's
registry, for a client's certificate) and its clock. Without an origin or a
binding it refuses (`verifier_misconfigured`), as it does for a client delivery
without the team key. It checks, in this order:

1. the `AWEB-Hook DIDKey` scheme (`wrong_scheme`), so an app-event or
   `hook-resolve` credential is refused at a hook target;
2. the signed payload is strict base64url and strict canonical JSON, and its
   signature is spelled exactly (`signature_encoding`) and verifies under the
   header's `did:key` (`bad_signature`);
3. `auth` is `hook-delivery` (`wrong_auth`);
4. the payload's fields, its `did_key` is the header's (`signer_mismatch`), and
   its `team_id` is well formed (`invalid_value`);
5. `aud` is the target's own origin (`audience_mismatch`);
6. method and path are the request's (`request_mismatch`);
7. `body_sha256` matches the body (`body_mismatch`);
8. the timestamp is within 300 seconds of the target's clock
   (`timestamp_outside_window`);
9. `binding_id` is the target's own binding (`binding_mismatch`);
10. the body carries a valid envelope of the credential's team, through the
    envelope checks above;
11. the envelope's `event_id` (`event_mismatch`), and its producer, `kid` and
    `did_key`, are the credential's (`producer_mismatch`);
12. for a client producer, the team certificate is present
    (`certificate_missing`), names the event's team, producer key and
    certificate id (`certificate_mismatch`), and is signed by the team's current
    key (`certificate_invalid`).

The target then checks that the binding is its own active registration, and
that the producer holds an active production for the hook (aweb-acgh.7).
