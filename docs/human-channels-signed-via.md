# P1 signed channel provenance

The signer asserts optional `via` provenance. It is display metadata, not proof
of platform authentication, custody, membership, routing or controller authority.
Authoritative sending-presence or channel-ingress facts determine whether a
message is bridge/host readable. Omitting `via` cannot change those facts or
remove a **not E2EE** label. Cloud D-UI/C3 owns that label.

P0's [native placement and grammar](human-channels-contract-v1.md#compatibility-bytes-and-signatures)
and [frozen vectors](vectors/human-channels-v1.json) remain unchanged. Plaintext
places `via` inside the signed payload; v2 places it only in protected inner
content. Unknown valid kinds are preserved as text; only known kinds map to
platform names/icons. Renderers escape unfamiliar text and grant no authority.

Athena's retained-payload decision (5112c837, relayed by integrations 7ef4550e):
no capability negotiation. Plaintext producers include `via` only on paths
proven to retain the original signed payload. Otherwise they omit it **before
signing**, including delivery to unproven remote/federated servers. A relay never
strips a field from an existing signed payload. Omission loses a label and must
not refuse the ordinary send. V2 has no such provenance gate: unchanged outer
signature/AEAD/header protection preserves compatibility.

## Retention inventory

Source inventory basis: `fa5ae8430b7f2120fec0242ffc93d7e006985edb`.
Paths below are relative to the repository root at that SHA. This first
inventory is source evidence; released-reader/server matrix runs are pending.
"Retains" means copies the original string, never reconstructs its JSON.

| Path | Source evidence | Initial state / verification hop |
| --- | --- | --- |
| REST mail acceptance | `server/src/aweb/routes/messages.py:494`, `:1925` | Requires payload with signature; passes original to storage. |
| Mail row / sender self-read | `server/src/aweb/messaging/messages.py:405`, `:427` | Retains string in messages; sender reads the same row. |
| REST inbox / exact inbox lookup | `server/src/aweb/routes/messages.py:2028`, `:324` | SQL selects raw string; response copies it. |
| REST single-message show | `server/src/aweb/routes/messages.py:2077`, `:2091` | Sender or recipient; same response builder. |
| REST mail conversation / history pages | `server/src/aweb/routes/messages.py:425`, `:441`, `:454` | Both page queries select raw string, shared builder retains it. |
| REST chat creation / send | `server/src/aweb/routes/chat.py:1695`, `:2853` | Passes original payload to shared writer. |
| Chat row / retained replay read | `server/src/aweb/messaging/chat.py:490`, `:511`, `:714`, `:731`, `:772` | Stores and returns original string. |
| REST chat history / exact-message read | `server/src/aweb/routes/chat.py:1909`, `:1990` | Copies raw string into message object. |
| REST chat stream, catch-up and live/poll branches | `server/src/aweb/routes/chat.py:2234`, `:2284`, `:2370`, `:2418` | Both branches carry original string. |
| Global actionable SSE | `server/src/aweb/routes/events.py:149`, `:191` | Metadata hint; channel fetches exact message before verification. |
| Channel mail event-then-fetch | `channel-core/src/channel.ts:683`, `:690`; `channel-core/src/api/mail.ts:46`, `:129` | Fetch exact inbox row, then verify original payload. |
| Channel chat event-then-fetch | `channel-core/src/channel.ts:782`, `:790`; `channel-core/src/api/chat.ts:39`, `:152` | Fetch exact history row, then verify original payload. |
| Pending chat / conversation list | `server/src/aweb/routes/chat.py:1766`; `server/src/aweb/routes/conversations.py:65` | Preview/discovery, no author-signature verification. Full-message read uses history/conversation hop above. No verified via derives from preview. |
| MCP mail inbox | `server/src/aweb/mcp/tools/mail.py:768`, `:136` | Retains original payload/signature through row projection. |
| MCP chat history | `server/src/aweb/mcp/tools/chat.py:1011`, `:1059` | GAP: drops payload/signature while projecting full message; fix within P1 projection scope. |
| MCP chat send-and-wait replies | `server/src/aweb/mcp/tools/chat.py:298`, `:324` | GAP: selects payload/signature then drops them in reply object; fix within P1. |
| MCP contact mail read | `server/src/aweb/mcp/tools/contacts.py:496`, `:512` | Retains through shared MCP mail projection. |
| MCP contact chat read | `server/src/aweb/mcp/tools/contacts.py:538`, `:550` | GAP: full-message projection omits source/signature; fix within P1. |
| Hosted MCP signer | `server/src/aweb/mcp/signing.py:233`, `:256`, `:272`, `:282` | Requires exact expected bytes; verifies and returns same string. |
| MCP local mail/chat sends | `server/src/aweb/mcp/tools/mail.py:375`, `:435`; `server/src/aweb/mcp/tools/chat.py:718`, `:903` | Preserves signer result into ordinary storage. |
| P2 prepared-send / ingress replay | `server/src/aweb/human_channels/http.py:134`; `server/src/aweb/human_channels/native.py:423`, `:459`, `:839` | Original envelope retained and bound by input hash; source payload passed through. |
| Federation outbound | `server/src/aweb/routes/messages.py:1028`; `server/src/aweb/routes/chat.py:729`; `server/src/aweb/federation/mail.py:65` | Carries original string in envelope; producer must omit via before signing for unproven remote. |
| Federation inbound / retained row | `server/src/aweb/federation/envelope.py:159`, `:169`; `server/src/aweb/federation/delivery.py:664`, `:728` | Requires/verifies original bytes, stores same plaintext string. Receipt replay reads retained row normally. |
| Go inbox / show / conversation | `cli/go/awid/mail.go:681`, `:701`, `:721`, `:782`, `:857` | DTO preserves raw string; shared normalization verifies it. |
| Go chat history | `cli/go/awid/chat.go:721`, `:735`, `:823` | DTO preserves and verifies original string. |
| Go chat SSE consumer | `cli/go/chat/chat.go:225`, `:315` | Verifies original string, but GAP: event output drops it. |
| Go chat CLI history/open/send event output | `cli/go/chat/chat.go:950`; `cli/go/chat/types.go:9` | GAP: after successful verification, Event projection drops source. Preserve it for downstream consumers. |
| Hermes / Pi / Claude | `packages/hermes-aweb-platform/adapter.py:9`; `channel-core/src/channel.ts:690`, `:790` | Hermes uses real aw readback; Pi/Claude use shared channel fetch/verify. Presentation follows verification, not a second signer. |

The shipped survey inspected aw 1.36.48 and 1.36.49 binary build revisions and
the actual npm @awebai/claude-channel 1.8.0 bundle. Their normal plaintext read
paths verify raw `signed_payload`; their missing-payload fallbacks rebuild known
fields and therefore fail via-bearing signatures. The Python awid-service
0.5.32 verifier accepts original bytes. No native mail/chat reader was found in
aweb-naapp 0.5.0. This inventory does not claim arbitrary remote retention.
