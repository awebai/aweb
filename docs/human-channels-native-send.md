# Native human addressing

Status: implemented here are human aliases in ordinary mail and chat, and
participant/key discovery at `GET /v1/messaging/participants/{alias}`. Not
implemented: a transactional native-send service. The `NativeMessagingService`
embedding and its routes `GET /v1/messaging/capabilities`,
`POST /v1/messaging/resolve`, `POST /v1/messaging/prepare` and
`GET /v1/messaging/ingress-results/{namespace}/{key}` were removed. Neither aweb nor
aweb Cloud configured the service, so resolve, prepare and ingress-results only
ever answered `authority_unavailable`, and capabilities only ever returned a
fixed list reporting the send facade as refused. Migration
`056_drop_native_send_tables.sql` drops the tables only that service wrote.

A human alias names the human's existing actor in the authenticated, selected
public team, under the [human-channel contract](human-channels-contract-v1.md).
It creates neither a principal nor a global address. The ordinary agent roster
remains agent-only. Unknown bare global DIDs still cannot establish a
first-contact route. Managed group membership, bridge guests, re-share and
federation remain separate capabilities.

## Actor and key discovery

Ordinary mail/chat aliases include active human actors in the selected team.
Global DID/address projections require the current identity-binding marker,
as on existing native reads; an unverified stored claim is withheld. Its raw
policy identity still selects the restrictive identity-wide inbound policy.
Qualified aliases do not select a different team's human. Existing native agent
selectors retain their behavior. HTTP and MCP use the same messaging-only
lookup and existing inbound policy. A revoked admitting certificate cannot
restore an alias; registry unavailability does not establish membership.

`GET /v1/messaging/participants/{alias}` returns the selected team's actor ID,
public team ID, alias, current DID projections, status and optional original
identity-signed encryption assertion. It is participant/key discovery, not
signing-custody proof. The server checks the assertion against the current
identity key, including fresh AWID resolution for a global identity; the Go
reader independently verifies its signature and, for a global human, requires
its signing key to match a fresh AWID key lookup through the selected team's
configured registry. Registry failure or a different key refuses encryption;
local humans retain server-roster trust. The result cannot
create a global address or remote route. A missing key permits plaintext alias
delivery but explicitly selected encryption refuses; it never retries plaintext.
