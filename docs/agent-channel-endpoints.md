# Agent endpoints and human channel choices

Status: **design candidate; no implementation or activation**. This records
Juan's 2026-10-31 endpoint decisions B, C and amended H. The amendment permits
any chosen set of channels per agent; it supersedes the earlier one-channel
recommendation. The human-side key is ONE human identity across teams.

Base reviewed: `b5a7c0afb78c4e3054d5c4c59cd952471da119ce`. Requirements below
are proposed interoperable behavior, not claims about deployed adapters.
The [email profile](email-channel-profile.md) specializes this model.

## 1. Identity, membership, endpoint and personal link

Let `S` be the agent identity and `H` the human's ONE registered `did:aw`, with
one canonical aweb address. Let `T` identify a selected team. Membership in T
is a relationship of H, not another human identity. An actor row, session key,
team alias or certificate is a local projection of that relationship. H's
identity namespace need not match T or S's namespace; joining another team
does not allocate another human address. This is a protocol requirement, not
evidence of hosted cross-namespace membership support: each consuming host
must prove that membership path before enabling it.

The existing [ID contract](id-certificates.md#1-what-the-tree-proves), lines
14–38, separates responsibility, custody and membership. Its human shape
requires `did:aw` (lines 58–59). The
[human binding predicate](human-channel-binding.md#3-full-current-human-predicate-for-bind-and-rebind)
remains the authority for the owner lane. This design adds neither human
issuance nor team membership from a channel credential.

| Relationship | Logical identity | Authority |
| --- | --- | --- |
| Agent endpoint | `(S, platform, mode, private binding target)` | Agent subject or verified responsible-human owner lane, plus resource checks |
| Human personal link | `(H, platform, private platform-account scope and account)` | Actual human account association, platform verification and explicit consent |
| Human delivery choice | `(H, S) → set of eligible personal links` | H's authorized choice; a default set for agents without an override |
| Team membership | `(H, T)` | Ordinary current membership and target-operation policy |
| Transport correlation | Private platform message reference → canonical aweb message ID | Exact recorded delivery/intake context, followed by current access checks |

No human-side relationship above is keyed on a per-team actor. Team/actor IDs
may accompany a request to check its current scope; they cannot select another
H or partition H's personal links and preferences by team. Choosing a channel
for S does not make H responsible for S, a contact, or a member of S's team.

One personal link can be reused across all agent endpoints in its verified
platform-account scope. Creating a second bot does not require another human
ID or a new personal association. Platform-required per-bot activation or
resource consent still applies; reuse is not permission to bypass it.
Tenant-scoped platform IDs are interpreted within that exact tenant scope.
Two similar names, email addresses or platform IDs in different scopes are
not an account association.

## 2. The agent endpoint

`platform` identifies the transport kind. `mode` is `native`, `dedicated` or
an explicitly approved `shared` mode. The agent's own native presence and its
bridge-managed dedicated account are distinct, even when named alike.
A shared bot with per-message display renaming is not a dedicated endpoint.
An agent has at most one active native or dedicated endpoint for a platform
within the same presence scope; existing scoped/native suppression rules apply.
A shared resource can carry separately authorized agent bindings.

The public records remain the existing
[presence and binding families](human-channels-contract-v1.md#presence-and-native-operation-records),
lines 374–423: exact subject, mode, platform/scope, blinded target commitment,
service audience, authorization revision, generation and request. Bot IDs,
mailbox-account mappings, tokens and private platform locators remain with the
adapter. These logical relationships are not a new public DTO or schema.

Per-agent identity is the default on each platform. Shared mode requires an
explicitly approved exception with its addressing and UX cost stated. The
email endpoint maps an existing agent address rather than creating another
identity; its profile defines DNS and mailbox constraints.

## 3. Attach, replace and detach (decision B)

There are two positive authorization lanes:

1. **Subject lane:** S authorizes its own endpoint with the existing signed
   subject operation and applicable grant restrictions.
2. **Responsible-human lane:** the actual human session is associated with H;
   the current shared verifier binds S's authenticated current key to H as its
   responsible human; H and S satisfy the operation's current team/access
   requirements. Under the ID tree, that ownership proof is the responsible-human
   result of S's current ID chain verified through AWID (`nearest_human` with
   `human_id=H`), so a hosted endpoint needs no separate portable owner artifact.
   Apply the full
   [current-human predicate](human-channel-binding.md#3-full-current-human-predicate-for-bind-and-rebind),
   lines 90–122, including consent, legitimate signing custody and resource
   verification.

A team administrator sets allowed-platform and guest policy. That role alone
cannot attach, replace or detach an agent endpoint, become its owner, or
sign as S/H. A platform token proves neither lane. Endpoint ownership does
not transfer the namespace controller or the agent's identity keys.

Apply each operation through the existing
[host transaction and P8 generation/request CAS](human-channels-presence-verification.md#applying-a-verified-result),
lines 101–145. Resolve external identity evidence before locks; recheck local
account/session, membership/removal, resource, custody and consent under the
existing lock order. A losing rebind/stop race cannot commit the old route.
Keep generation tombstones and original-result recovery; a retry cannot
reactivate a detached endpoint. Ownership change requires fresh authority,
not inheritance of the old owner's proof or private token.

Stopping one's own personal delivery link remains the existing reducing
operation, including after membership loss or unavailable human evidence
([human-channel-binding §5](human-channel-binding.md#5-change-stop-and-removal),
lines 171–205). This does not waive portable unbind checks or authorize that
person to take over, rebind or detach another agent's endpoint. An authorized
host may disable a route under existing operator policy without impersonating
its owner.

## 4. Who may enter (decision C)

An endpoint is a transport route, not an admission grant. Admission is:

`current agent inbound_mode AND endpoint restriction AND host/platform policy`

The endpoint restriction defaults to no additional restriction and may only
narrow the agent's policy. Identity-wide `inbound_mode` remains exactly the
[existing delivery contract](identity-messaging-contract.md#authority-boundaries),
lines 49–75: `open`, `team_and_contacts`, or `contacts_only`, with missing or
invalid policy refusing. Team ownership alone cannot change it. A link or
outbound channel choice never creates an implicit contact.

For a linked human, apply that policy to H, its current membership or exact
contact evidence, and the same current author/route checks used by the native
path. Do not test the bridge or a per-team shadow human in H's place.
Responsibility for the receiving agent is not required just to message it.

An unlinked platform speaker remains a typed bridged guest with
`external_untrusted` assurance. Guest entry additionally requires BOTH
endpoint opt-in and team/host allowance. These flags cannot widen
`team_and_contacts` or `contacts_only`: if the guest cannot meet the existing
policy, refuse. A separate guest policy or guest-contact capability needs its
own contract; it is not inferred here.
The [existing guest contract](human-channels-contract-proposal.md#unlinked-people-and-external-only-agents-a-versus-b),
lines 121–208, still requires authorized guest/session scope and compatible
consumers. In particular it does not admit a guest into native two-party mail.
An email guest therefore has no native-mail bypass.

Recheck admission at intake/commit, not just when attaching the endpoint.
Removal from T ends T-derived access without deleting H or links used in other
teams. Preserve existing account-owned stop and opt-out tombstones; observing
another platform message cannot relink or reactivate a stopped account.

## 5. Several channels for the same human (amended decision H)

H chooses a default **set** of personal links and may override it for S with
any set of that human's links. An absent override uses the default; an explicit
empty set selects no external copies. These preferences do not suppress the
canonical aweb mailbox or authorize new access. An eligible channel also needs
the agent endpoint and any platform-specific activation/export consent.

One accepted aweb message keeps one canonical message ID, conversation ID,
author and audience. Deliver a copy through each distinct selected eligible
link. Duplicate copies on different selected channels are intentional. Within
one selected delivery target, retry uses the existing stable delivery identity;
a duplicate configuration row is not another requested copy.

A selected channel's failure does not silently reroute to an unselected
channel, widen the audience or resend the canonical message. Report outcomes
per channel using the adapter's durable delivery/recovery behavior. A detached
or revoked link stops future copies, including queued old routes according to
existing cutoffs. A settings change does not replay historical messages.
"Answered elsewhere" synchronization is deferred: a reply does not cancel,
mark read or acknowledge copies on other platforms automatically.

## 6. Reply from any channel

Each delivered platform message/part maps privately to the exact canonical aweb
message ID, endpoint generation, H/S and conversation. A reply on any linked
channel resolves that message first, then continues its recorded conversation.
It is not routed to the pair's newest thread, a subscription's fixed thread,
a subject match, or the last active conversation on another channel.

Correlation is a locator, not authorization. Verify the actual platform
speaker/link, H, target S, current thread participation and delivery permission
before signing and committing. A reply reference belonging to another human
or endpoint cannot grant history or participation. Two different human replies
on two platforms are two messages, not a retry of one another.

Thread identity is `conversation_id`; the subject is a title, never a routing
key. Starting a thread and continuing one are separate actions. The originating
adapter resolves correlation before constructing the signed native message;
it cannot rewrite a signed conversation ID later. This preserves
[original native envelope bytes](human-channels-native-send.md#public-embedding),
lines 92–115, and the existing reply-correlation rule
([human-channels-contract-v1.md](human-channels-contract-v1.md), lines 439–440).
A platform's fresh-message/thread UI belongs to its reviewed profile; there is
no generic "latest thread" fallback. The email rules appear in its profile.

## 7. Moving existing per-team bindings to ONE H

This is a required migration contract, not permission to run a data migration.
The consuming implementation must supply its exact schema and measured
inventory before rollout. Today the
[native selector](human-channels-native-send.md#actor-and-key-discovery) uses
selected-team human actors; the proposed one-H model supersedes their use as
personal-link/preference identity keys. Existing signed statements remain as
originally authored.

1. **Inventory:** enumerate old account-owned platform links, per-agent choices,
   actor/team references, pending deliveries/correlations, stops and consent
   generations. Produce counts of mapped, conflicting and unresolved records.
2. **Establish H:** use the human-ID feature's verified account→ONE-H adoption
   result, not matching email, alias, owner label or an old actor ID. Obtain
   current membership projections for each retained team. Do not mint an H per
   team or revive an old team actor as a second human ID.
3. **Associate existing resources:** verify the authenticated account controls
   each exact existing personal link and that its resource, consent and stop
   state remain valid. Retain original evidence; an old signature over actor A
   is not a signature by H and must never be rewritten. Obtain new H-bound
   authorization for positive binding operations where the existing proof
   does not authorize them.
4. **Resolve collisions:** coalesce only demonstrably identical links for the
   same H/platform-account scope and private resource. Never union conflicting
   channel choices, undo a stop or transfer another account's resource. The
   human explicitly resolves conflicts; unresolved records stay unmigrated.
5. **Cut over atomically per migrated binding:** store the H association and
   `(H,S)` choice; update the current team actor lookup separately. Switch new
   ingress/delivery to H in the same transaction that disables the old binding
   path. Preserve generation/replay tombstones and committed-delivery identities
   so neither copy nor intake is duplicated. Recheck authority under locks.
6. **Retain exact reply lookup:** legacy provider references can remain as
   historical locators. For a reply, resolve the original message/conversation,
   then authorize the current H and current participants under the identity
   migration's reviewed continuity rule. If continuity or access is unproven,
   refuse; do not guess it from a legacy actor. Keep original signed history and
   attribution. This design grants no historical access by migration alone.
7. **Verify and retire:** prove old and new entry points use the same H, with
   cross-team and cross-channel replies and zero duplicate effects. Report
   before/after/unresolved counts. Retire the obsolete per-team write/selection
   path after its consumers migrate; do not keep an alias or fallback resolver.

Until a binding's cutover, its released path and existing restrictions remain.
No new endpoint/human-owner feature may use an unverified legacy actor fallback.
If H adoption or required proof is pending, leave the migration pending and
keep it visible; do not silently manufacture authority. Narrowing or removing a
released path requires the separately reviewed consumer rollout.

Shared-to-dedicated bot migration is a different axis. A deliberate per-agent
cutover makes the dedicated route win and retires the old shared route for that
agent; when the last agent migrates, remove the shared bot/addressing path on
the operator's approved timeline. This does not silently change H's chosen
channel set or duplicate a single platform target.

## 8. Acceptance and implementation boundary

Before activation, consumer tests must cover: owner/subject success; wrong
human/admin/token refusal; current removal with surviving actors; own stop
after removal; two teams sharing H and one personal link; per-agent multi-set,
default and empty override; one-channel failure; revocation versus queued send;
replies on both channels to two simultaneous threads with identical subjects;
wrong-H correlation; migration conflict, stop retention, original-history
attribution, restart/exact retry and one-path cutover.

Use the existing P8 verifier/transaction interfaces. No new route, signature
family, database migration, platform credential or production write is added
by this document. Identity adoption, host bindings, platform provisioning and
UI implementation follow design review. The email extension requires its own
published profile, vectors and consuming artifacts before email activation.
