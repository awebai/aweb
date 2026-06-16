# Aweb Control Plane And Apps

Product sentence for restructuring advice:

> aweb.ai is where humans create and manage agent teams. Agents use apps.

The human-facing hosted site should be one control plane for accounts, orgs,
hosted teams, custodial identity creation, OAuth/MCP consent, app installs,
quota, payment, namespaces, and admin/security views. It should not own every
app's domain state.

Custodial identity is not itself billing or ownership. Custody is the identity
key custody mode: in a custodial identity, the hosted control plane generates,
encrypts, stores, and signs with the agent identity key on behalf of the actor.
Billing, ownership, and quotas attach to the hosted organization/team/control
plane around that identity.

The main near-term use case for custodial identities is hosted MCP access from
clients such as claude.ai or chatgpt.com where the agent cannot manage a local
key. The human OAuths to the aweb.ai MCP server, the control plane binds the
grant to a hosted addressed/global custodial identity, and the hosted MCP
gateway exposes tools for the apps that identity/team is allowed to use. Tool
calls are signed by the custodial identity and forwarded to core/apps.

Future hosted runtimes, n8n, Copilot, and other integrations can reuse custody
without necessarily using OAuth. The invariant is that the hosted control plane
holds signing authority for a named agent identity and binds that authority to
a specific external runtime, connector, service account, or delegated grant with
auditable scopes and revocation.

Supported binding patterns should not be OAuth-only. The control plane may bind
external runtimes/connectors to a hosted custodial identity through:

- OAuth grant to custodial identity
- API key bound to custodial identity
- OIDC workload identity
- signed webhook binding
- service account binding
- delegated token with narrow scopes
- one-time device/code flow
- explicit admin-created connector grant

The invariant is: this external runtime is authorized to act as this hosted
custodial identity, within these scopes, until revoked. The raw identity key is
never given to the external runtime or to apps.

A2A is Agent2Agent interoperability for the open agent web, not aweb chat/mail
and not org-to-org federation. Core/AWID owns A2A publication assertions,
directory/discovery facts, address-to-Agent-Card route/digest/delegation
bindings, and verification. The hosted gateway owns `aweb-a2a-gw` as a bridge
that exposes aweb identities to standard A2A clients. The CLI owns `aw a2a` for
outbound A2A calls and card verification/publication. Hosted A2A gateway usage
is billed only as ordinary bundled hosted mutations.

Hosted teams and BYOT are two modes for team/web authority custody, separate
from agent identity custody:

- Hosted team/web: aweb.ai manages the team/web controller authority. This is
  the default product path for humans. The control plane can create teams,
  create/admit hosted custodial identities, issue/revoke certs, install apps,
  and connect hosted MCP flows directly because it has the managed team
  authority.
- BYOT: the team/web controller authority lives outside aweb.ai. aweb.ai may
  connect to, display, meter hosted usage for, and help operate that team only
  within the authority explicitly delegated by the external controller.

Custodial identity is orthogonal to hosted/BYOT team authority. A hosted team
can contain self-custodial local agents; a BYOT team can contain a hosted
custodial identity only when the BYOT controller admits it or delegates that
authority to aweb.ai.

Hosted MCP for BYOT is therefore not automatic. The hosted control plane may
create a custodial identity key, but it cannot mint a valid team certificate for
that BYOT team unless the external controller approves/adopts the identity or
has granted a limited delegation. The UI should present explicit capability
states: hosted-managed, BYOT-connected/read-only, BYOT-delegated, and migrated
to hosted authority.
