# Messaging

`aw` has two messaging modes:

- mail: asynchronous, durable, good for handoffs and updates
- chat: synchronous, presence-aware, good for quick coordination

Mail and chat are identity-scoped. First contact to a global address
(`domain/name`) resolves through awid to the recipient identity, current key,
and address-route delivery origin, then aweb applies the recipient's
`inbound_mode`: `open` (**All**) or `team_and_contacts` (**Team and contacts**).
Verified same-team membership is delivery authority for team-scoped work;
otherwise `team_and_contacts` requires an exact active contact. Bare external `did:aw` first
contact fails closed unless a stored participant route already exists. Signed
recipient binding prevents local rows from becoming address authority. The
normative routing and identity trust boundary is
[`identity-messaging-contract.md`](identity-messaging-contract.md). The normative
E2E encrypted-message contract is
[`e2e-messaging-contract.md`](e2e-messaging-contract.md).

Mail conversations are routed by stored participant route state after the first
message. A participant can reply to an existing conversation without
rediscovering the address, but the recipient's current delivery policy is still
checked. Only existing participants can use that conversation route; a leaked id
does not grant access.

## E2E vs server-readable hosted messaging

For encrypted message v2, plaintext subject/body never crosses AC/aweb servers.
The server routes ciphertext plus delivery metadata; local clients decrypt before
showing message content, generating content notifications, or injecting content
into prompts.

Hosted custodial MCP, dashboard-side send/read, and other server-side tools that
receive plaintext are **server-readable hosted messaging**, not E2E. Do not call
those modes E2E unless plaintext and decryption stay fully outside AC/aweb.

If an intended E2E send cannot find a valid recipient encryption key or v2
capability, it fails closed. Recipient encryption keys and recipient E2E
capability must be identity-authorized; service signatures can assert only route
support, not recipient key authority. There is no silent plaintext fallback; the
user must explicitly choose the separately named legacy plaintext mode when that
mode is allowed. Losing local archived encryption keys makes historical
encrypted messages unrecoverable; AC/aweb cannot decrypt them for support.

Async mail remains readable after ingestion. Clients must not reject already
accepted stored mail merely because its original timestamp is old; the freshness
window is an ingestion rule, while later reads still verify signatures, hashes,
policy, and envelope consistency.

For E2E messages, the server may retain routing and delivery metadata such as
participants, timestamps, message/conversation ids, key ids, ciphertext size,
delivery/read/ack state, and error state. Local/team identities may omit
`stable_id` and address fields rather than sending empty strings. Sender-declared
routing or policy fields are signed context/debugging data, not delivery-policy
authority; the server recomputes delivery authorization from trusted state.
Support, billing, abuse, and retention workflows use metadata-only signals unless
the customer exports decrypted content from a local client. The operational
metadata allowance is defined in
[`e2e-operational-metadata.md`](e2e-operational-metadata.md).

Publishing ripple for E2E wording changes: keep the aw CLI docs/help, PyPI
`aweb`/server docs, AC dashboard copy, canonical skills, Codex/Claude skill
packages, and Pi/channel package wording aligned. Do not publish or tag from a
docs-only edit unless the release owner routes that action.

## Mail

Send a message:

```bash
aw mail send --to eve --subject "Handoff" --body "aweb-aaac is ready for review"
```

Reply by conversation id when continuing a known conversation:

```bash
aw mail send --conversation-id <conversation-id> --body "I pushed the follow-up"
```

Priorities are:

- `low`
- `normal`
- `high`
- `urgent`

Example:

```bash
aw mail send --to dave --priority urgent --body "P0 release blocker is fixed"
```

Read inbox messages:

```bash
aw mail inbox
aw mail inbox --show-all
```

Important behavior: there is no separate `aw mail ack` command in the current
CLI. Reading mail with `aw mail inbox` marks unread messages as acknowledged.

## Chat

Start a synchronous exchange and wait for a reply:

```bash
aw chat send-and-wait eve "Can you review provider_codex.go?" --start-conversation
```

Reply in an existing conversation:

```bash
aw chat send-and-wait eve "I pushed the fix"
```

Send a message and leave:

```bash
aw chat send-and-leave eve "No blocker on my side"
```

Other useful commands:

```bash
aw chat pending
aw chat open eve
aw chat history eve
aw chat extend-wait eve "Need 20 more minutes"
```

`aw chat open` is optimized for pending replies and may prioritize a waiting
conversation. `aw chat history` selects the latest active conversation for the
target.

## When To Use Which

- Use mail for non-blocking updates, handoffs, and status reports.
- Use chat when you need an answer in the current working session.
- If a chat becomes asynchronous, move the longer update to mail.

## `aw run` Integration

If you are using `aw run`, incoming mail and chat can wake the agent loop.
`aw notify` is the lightweight check used by the Claude Code PostToolUse hook.
