# aw-hooks: catalog, bindings and delivery

Status: **specified experimental public contract, not yet shipped**. Owner: the
aweb OSS hooks lane (aweb-acgh.16). This document is the source of truth for the
`aweb.hooks` catalog, version 1, for owner-activated hook bindings, and for how
a producer delivers hook events. Its machine-readable authority is two vectors:

- `docs/vectors/hook-catalog-v1.json`: the hooks, their payload allowlists and
  rules, with positive and negative cases;
- `docs/vectors/hook-binding-cases-v1.json`: binding states, activation, the
  `active_from` pad and revocation, as replayable cases.

The strict reader is `aweb_naapp.hooks.catalog`
(`naapp-lib/src/aweb_naapp/hooks/catalog.py`). The design and its rationale are
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
may echo, a credential. `request_sha256` and `params_sha256` cover the request
**before** credential injection. Response bytes are committed only through a
producer-keyed HMAC (`upstream_response_hmac`, `returned_hmac`).

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
- `refused` requires `refusal_code`, from the catalog's 28 codes; no other
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
`request_sha256` and `http_status` are required. `request_sha256` is the
SHA-256 of the canonical request bytes of the manifest mapping. Parameter
values are not copied; the digest commits to them. A refusal carries no
`result_ref`.

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
  signed by the team's controller authority. The owner-act contract is
  aweb-acgh.16.3. Any other signer is refused with `owner_required`. Activation
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
to that binding and event. The envelope's signing bytes and the credential's
fields are fixed by docs/vectors/hook-event-envelope-v1.json and
docs/vectors/hook-delivery-credential-v1.json (aweb-acgh.16.2). Egress takes
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

Every event is one signed envelope, `aweb.hook-event/1`, carrying:

- the catalog id and version, and the hook;
- `event_id`;
- a `trace` with a W3C trace id and its origin;
- `team_id`;
- the `producer`: its kind, origin or member identity, key and `seq`;
- the `actor`, with its authority mode and any verified attestations;
- `occurred_at` and `fired_at`;
- `result_status`;
- the payload above.

For a client event, the actor is the member who signed it. aweb-acgh.16.2 pins
the canonical bytes, the signature and their vectors.
