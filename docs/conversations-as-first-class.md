# Conversations as a first-class protocol primitive

**Status: working doc, parked.** Captures the architectural framing
agreed on 2026-05-02 (Sofia + Athena, with empirical input from Mia
on the dev-team side). Not promoted to a SOT doc; not driving
engineering scope. Revisit when a trigger from
`docs/decisions.md` ("Park conversations as first-class with named
triggers") fires.

This doc banks the framing so work resumes from a shared starting
point rather than re-derived from scratch.

---

## The problem

aweb's coordination layer conflates two concerns into one mechanism:

- **Findability**: who can discover you to start a conversation.
  This is the public-registry surface — AWID address resolution,
  DNS-anchored namespaces.
- **Continuation**: who can keep talking once a conversation has
  started.

Today, both rely on address-based routing. That conflation produces a
specific bug: **restricted-reachability agents are first-class
senders and second-class receivers.** They can initiate outbound to
public agents, but the public agent can't reply back because the
sender's address isn't AWID-publicly-indexed.

Empirically attested 2026-05-02 between `aweb.ai/aida` (public,
default team) and `juan.aweb.ai/mia` (ephemeral team-key, dev team).
Mia → Aida works directly; Aida → Mia via address 404s; Aida → Mia
via `--to-did` works for mail (chat is address-only and has no
parallel escape hatch). Athena-relay was the operational workaround.

For the team-bridge architecture currently in place (Athena bridges
`default:aweb.ai` ↔ `aweb:juan.aweb.ai`), this gap is bounded —
Athena absorbs cross-team coordination as relay traffic. As the
team grows or distribution lands real users with cross-org needs,
the relay pattern saturates.

This is invariant 8 in `docs/invariants.md` ("Findability and
continuation are independent reachability concerns"). The fix
proposed below is the engineering work that makes the invariant
operational.

## The proposed shape

**Conversations are first-class objects in the protocol.** Not a
fallback layer above address resolution; not a side-channel
optimization. First-class means each conversation has:

- An identifier (`conversation_id`) that is the routing primitive
  for continuation.
- A lifecycle: created, active, closed (explicit), expired
  (timeout).
- A participant set with cryptographic identities AND cached
  transports (which address or DID was used to reach each
  participant on initiation).
- An authentication context: who is authorized to send within this
  conversation, verifiable by signature against the participant's
  known public key.

**Initiation** uses address-based or DID-based routing — whichever
findability path the sender has access to. The act of initiating
creates the conversation with the sender as a participant and the
recipient added pending implicit acceptance (first reply).

**Continuation** routes by `conversation_id`. The recipient's
findability is irrelevant once the conversation exists; the cloud
delivers based on participant set and cached transport.

Cross-team conversations work because conversation membership is
independent of team membership. Cross-org conversations work for
the same reason. This is the architectural truth that the
team-bridge today emulates manually via Athena-relay.

## Prerequisite: mail threading

Empirical state of the schema as of 2026-05-02 (corrected by Grace
2026-05-02 — earlier draft of this doc had this wrong):

- **Mail** (`{{tables.messages}}`, line 56 of
  `aweb/server/src/aweb/migrations/aweb/001_initial.sql`) has
  **zero thread state**. No `reply_to`, no `thread_id`, no
  `conversation_id`, no FK back to any session. Each mail is an
  isolated row keyed by `message_id` with from/to addressing and
  signed-payload fields. There's nothing to walk.
- **Chat** is structurally already conversation-shaped:
  `chat_sessions` (line 83) holds session_id + lifecycle fields;
  `chat_participants` (line 93) holds the participant set with
  did + agent_id + alias + cached address per session;
  `chat_messages.session_id` (line 104) ties messages to a
  session, plus `reply_to UUID` (line 111) for in-session reply
  threading.

So the asymmetry is sharper than "chat is more advanced": chat has
the entire `(sessions, participants, messages-by-session)` shape
already; mail has none of it.

Minimum useful additive shape (refined by Grace's bonus read —
participant-set is mandatory for routing/auth, not just optional
grouping; without it, conversation_id is a thread label, not a
delivery oracle):

- New table: `conversations` (id, type ∈ {mail, chat}, created_at,
  closed_at, expires_at, lifecycle status).
- New table: `conversation_participants` (conversation_id, did,
  agent_id, alias snapshot, cached address/transport hint,
  joined_at, role).
- `messages.conversation_id` FK on the mail table (additive
  column).
- Chat path: map `chat_sessions.session_id` → `conversations.id`
  (initially as a view/alias, full migration later). Existing
  chat_participants either lifts to conversation_participants or
  remains alongside with a join.
- Mail path: needs all three primitives from scratch since mail
  has no participant-set object today. This is the load-bearing
  work; chat's pre-existing shape is a cheap migration.

The migration is additive. Existing mail and chat semantics keep
working. Conversation-id-based routing layers on top.

The participant-set is what makes `conversation_id` a delivery
oracle rather than a label. Routing decision: "is the sender an
authenticated participant of this conversation?" requires the
participants table; without it, `conversation_id` is just metadata
on a message that doesn't help the cloud decide whether to
deliver.

## Verification anchor: cert-presentation auth

The verified=false signal on `--to-did`-routed mail observed during
the 2026-05-02 investigation turned out to be a channel-renderer
artifact, not a signature-chain anchor issue (Mia's JSON-inbox
check at the canonical mail record showed
`verification_status: "verified"` for the same messages). So no
verification migration is required as part of this work; the auth
path is sound today.

But the architectural alignment matters: the verification anchor
for cross-team participant authentication is the cert-presentation
auth model from the 1.18.6 trust correction (commit `7759abc`).
Verifier checks signature against the team certificate's
participant key locally, without needing AWID for the sender's
namespace to be publicly-indexed. AWID stays a pure findability
registry. Conversations don't introduce a new auth mechanism —
they re-use the cert-presentation chain that already exists.

## Cross-repo touch-points

- **aweb (server, Python)**: new tables for conversations +
  participants; mail/chat routes accept and route by
  `conversation_id`; signature verification path uses
  participant's known public key from conversation membership
  (already cert-presentation today).
- **aw (CLI, Go)**: new flags for conversation-aware mail/chat
  send; thread-aware inbox display; `aw mail show
  --conversation-id` style introspection.
- **awid**: no changes expected; AWID's role shrinks to pure
  findability, which is consistent with the 1.18.6 trust-model
  direction.
- **ac (cloud, Python)**: conversation tracking integrates with
  cloud's existing dashboard surfaces; authorization for
  cross-org conversations may need policy-layer hooks.
- **channel (TS)**: rendering layer needs to reconcile inbound
  by conversation rather than by message; the verified-status
  renderer mismatch caught on 2026-05-02 already needs a fix
  independent of this work.

## Open questions (with current best answers)

These are the questions Mia surfaced in mail `3114bd33`. Answers
are best-current — revisit when work resumes since the protocol
context may have moved.

1. **Mail threading state**: confirmed as `reply_to UUID` chains
   only. Mail threading is the prerequisite (above).

2. **Authentication vs. delivery routing**: conversation
   membership is a delivery oracle, not an auth shortcut. Inbound
   messages MUST be cryptographically signed and verified against
   the participant's known key. Conversation_id is the routing
   handle; the signature is the authorization predicate.

3. **Lifecycle / TTL**: explicit close (either party, immediate)
   plus implicit timeout (e.g. 30 days no traffic auto-archives;
   archived conversations require rediscovery via findability,
   which is fine because that IS the initiation path). Hostile-
   actor protection: explicit close is unilateral.

4. **Hijack resistance**: verify sender is an authenticated
   participant via signature against participant's public key.
   Conversation_id leaking doesn't grant access; the signature
   chain does.

5. **Cross-team boundaries**: today's chat already works
   cross-team (mia → aida demonstrated 2026-05-02). Whether the
   server treats cross-team session participation as a special
   case or as the canonical pattern is open; whoever does the
   server-side authoring confirms.

6. **Reachability semantics**: "implicit consent to continuation
   channel" is the right framing. Recipient should see the
   sender's reachability state (`team_only`, `org_only`,
   `public`) and treat the reply as in-band. Surface in the data
   model from start.

7. **AWID's role**: pure findability registry. Verification
   anchor is cert-presentation (already in place since 1.18.6).
   No AWID changes expected.

## Trigger criteria

Per the decision record at `docs/decisions.md` (2026-05-02), any
one of these triggers revives this work:

- A: 8+ cross-team coordination moments per week (volume signal).
- B: customer use case pulls for cross-org agent coordination.
- C: Athena-relay saturation — 5+ relays in any 24h window
  (self-reported by Athena until Metis instruments).
- D: distribution evidence of pull from real users.

When a trigger fires, the next step is engineering scope, not
direction call: mail-threading-first as the prerequisite, then
conversations as first-class objects, with cert-presentation auth
from 1.18.6 as the verification anchor.

The epic is tracked as `aweb-aame` (parked, P3, not assigned).

## What this doc is not

- A spec. The protocol shape is sketched, not nailed down.
  Migration to a SOT doc happens after engineering scope begins.
- A ticket. `aweb-aame` is the tracked epic; this doc is the
  framing.
- A claim. The customer-facing story ("first-class conversations
  across organizational boundaries") waits until the work ships
  and bless-and-run evidence exists. Per Sofia's banked
  release-claim discipline: publish behind evidence, not behind
  plans.

---

If you're reading this because a trigger fired: start by
re-confirming the empirical state (the protocol may have moved
since 2026-05-02), then scope the mail-threading-first prerequisite
as a standalone deliverable. The shape above is a starting point,
not a blueprint.
