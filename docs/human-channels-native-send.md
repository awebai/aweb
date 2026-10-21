# Native human addressing and transactional ingress

This is P2's implementation of the native families in the
[human-channel contract](human-channels-contract-v1.md). A human alias names the
human's existing actor in the authenticated, selected public team. It creates
neither a principal nor a global address. The ordinary agent roster remains
agent-only. Unknown bare global DIDs still cannot establish a first-contact
route. Managed group membership, bridge guests, re-share and federation remain
separate capabilities.

## Actor and key discovery

Ordinary mail/chat aliases include active human actors in the selected team.
Qualified aliases do not select a different team's human. Existing native agent
selectors retain their behavior. HTTP and MCP use the same messaging-only
lookup and existing inbound policy. A revoked admitting certificate cannot
restore an alias; registry unavailability does not establish membership.

`GET /v1/messaging/participants/{alias}` returns the selected team's actor ID,
public team ID, alias, current DID projections, status and optional original
identity-signed encryption assertion. It is participant/key discovery, not
signing-custody proof. The server checks the assertion against the current
identity key, including fresh AWID resolution for a global identity; the Go
reader independently verifies its signature and binding. The result cannot
create a global address or remote route. A missing key permits plaintext alias
delivery but explicitly selected encryption refuses; it never retries plaintext.

`ResolveRequest.team_id` and `AuthorityFacts.team_id` accept the canonical
lowercase `name:namespace` string as well as the UUID strings accepted by P0.
Session-only typed selectors remain structurally valid without a filler team;
this native implementation refuses them as unsupported until the managed
session implementation is enabled. Existing conformance bytes are retained.

## Public embedding

Construct `aweb.human_channels.native.NativeMessagingService` with the normal
OSS database infrastructure, a configured `ServiceBinding`, and a
`NativeMessagingAuthority` provider from `aweb.human_channels.authority`.
The provider resolves its own authoritative identity/custody/access data; it
never reads OSS tables. Candidate `NativeMessagingSubject` values are lookup
input, not proof. The returned `AuthorityFacts` must match the exact actor,
principal, current signing key, public team and configured service audience.
Unknown authority refuses; it never defaults to self custody.

Signing-key custody is independent of the encryption-key assertion's custody.
Native author verification remains native verification. Confidentiality also
accounts for server/host/bridge access and decryption custody. Encrypting the
wire to a hosted actor never makes the human-facing conversation E2EE.

The provider has three methods:

```python
async def current(auth, subject: NativeMessagingSubject) -> ContractRecord:
    ...  # AuthorityFacts; network/key lookup can happen here

async def lock_authority(auth, prepared: ContractRecord,
                         ingress_key: ContractRecord, transaction) -> None:
    ...  # current host-owned locks/rechecks on this exact asyncpg connection

async def authorize_recovery(auth, ingress_key: ContractRecord,
                             transaction) -> None:
    ...  # current recovery authority, before any original result is returned
```

`lock_authority` receives fresh snapshots of the retained, validated preparation
and authenticated ingress key. It locks/rechecks the host's account/session,
link, organization policy/consent, actor/signing custody and private binding
revision as applicable. It performs no network operation or independent
transaction. These locks last through the caller's own correlation/delivery
intent writes and `finish_ingress`/commit. A TTL or revision snapshot alone does
not replace the hook. Provider context is immutable per operation, stateless,
or keyed to the exact authenticated issuer and preparation/ingress; concurrent
requests must not share a mutable current-route slot.

```python
prepared = await service.prepare(auth, prepare_request)
async with service.unit_of_work(auth) as uow:
    result = await uow.claim_ingress(ingress_key)
    if result is None:
        accepted = await uow.accept(prepared)
        result = make_ingress_result(ingress_key, accepted, own_result)
        await own_repository.write(uow.transaction, own_result)
        await uow.finish_ingress(result)
```

Preparation verifies native signatures/recipient bindings and preserves the
original signed payload, envelope/ciphertext, UUID, kind and conversation ID.
Plaintext uses a canonical `SignedArtifact` containing the existing signed
native payload. Encrypted-v2 uses the existing canonical native envelope and a
current valid recipient key assertion. No signature or AAD is replaced.
Retained preparations expire after five minutes and are bound to the exact
caller and content. Losing one permits preparation of the same original bytes;
it does not permit a new logical send under the old ID.

The UoW serializes the authenticated issuer/namespace/key, rechecks host
authority and locks current OSS actors/policy/session facts. A prepared native
pair cannot silently send to an existing group's wider audience. Message,
conversation/session effects, attachment bindings, caller-owned writes, original
result and durable mutation intent share the same PostgreSQL commit. The
exposed `transaction` is the actual connection for the embedding's own tables;
there is no private insert hook. Exceptions or unfinished claims roll everything
back. An issuer mismatch refuses before result disclosure. Grant send scopes
and expiration still apply.

Exact ingress replay returns the original committed `IngressResult`. An input
hash conflict refuses. Stable message-ID replay binds the exact envelope,
author, kind, recipient, conversation and attachment refs, and creates no second
message or mutation intent. Another caller's result is never disclosed.
Recovery checks current requester authority and never revives an old route.

## HTTP, MCP and publication

Set `app.state.human_channels_service` to the configured native service to use
`POST /v1/messaging/resolve`, `POST /v1/messaging/prepare`, and authenticated
`GET /v1/messaging/ingress-results/{namespace}/{key}?input_hash=...`.
`GET /v1/messaging/capabilities` distinguishes the installed alias feature from
the configured transactional facade. Missing custody/access configuration
refuses the facade rather than inferring authority.

Existing native mail and pair-chat HTTP sends opt into the facade with all
three headers: `X-AWEB-Ingress-Namespace`, `X-AWEB-Ingress-Key`, and
`X-AWEB-Ingress-Input-Hash`. Partial sets refuse before effects. These calls need
fixed message/conversation IDs and the original signed native envelope. The
issuer comes from authentication. Replays compare the protected ID, kind and
envelope hash before returning the original acceptance. This is remote stable-ID
recovery, not atomicity with a caller's remote database. The caller persists its
own remote intent first and reconciles a timeout through the result read.

For hosted MCP ingress, pass `human_channels_service` to `create_mcp_app` and
supply the same headers. Ordinary `send_mail`/`chat_send` then use this UoW before
session or message insertion. The authenticated key determines stable message
and initial-conversation UUIDs. Original-result recovery also compares the
canonical logical tool input before signing again. Changed tool input refuses.
Explicit encryption requires the hosted encryptor; no plaintext fallback is
available. Legacy calls without ingress headers keep their existing behavior.

Committed mutation intents are published only after commit. Supply an async
`publisher(mutation_id, event_type, context)` which raises on delivery failure;
call `service.publish_pending()` on startup and on retry. The sink deduplicates
stable intent/message IDs for logical usage and side effects. A publication
failure leaves the durable intent pending and does not report a rollback of an
already accepted send. Event hints are at least once; no exactly-once model/tool
execution is promised. A legacy callback which swallows errors is not a durable
publication acknowledgment.

The existing public acfn attachment backend validates staged immutable refs and
binds on the same transaction, without network access. No provider URL, token,
platform account ID or replacement wire descriptor is introduced.

Migration `039_native_send_ingress.sql` adds the result, message-ID binding and
publication-intent stores. P3's native-only participant gates remain in force.
