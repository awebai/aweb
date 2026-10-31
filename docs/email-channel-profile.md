# Email platform profile for agent endpoints

Status: **design candidate; additive profile proposal, not enabled behavior**.
Base: `b5a7c0afb78c4e3054d5c4c59cd952471da119ce`. This implements decision F's
address shape in the proposed [agent endpoint model](agent-channel-endpoints.md).
It specifies public behavior; no mail provider, hosted schema or deployment
runbook is a protocol authority.

## 1. Address and routing authority

An enabled endpoint for the agent at `namespace/name` receives email at
`name@namespace`. For example, `lab.example/alice` maps to
`alice@lab.example`. There is no automatic `name+namespace@another-domain`
alternative and no fallback to a shared mailbox with guessed agent selection.
Only the exact registered/enabled address is a recipient. Catch-all transport
acceptance does not allocate an agent, H, team membership or consent.

The namespace and name must already be valid under the aweb address contract;
this profile's initial mailbox form additionally requires an ASCII SMTP
`dot-atom` local part within SMTP length limits and a DNS domain represented
in its canonical ASCII form. Names outside that intersection are unavailable
under this initial profile, not lossy-transformed into another name. A later
quoted-local-part or internationalized-email profile requires review. Preserve
the exact registered local part; no mailbox-provider dot folding, plus-tag
stripping or implicit aliasing. Use canonical domain handling, not suffix
inference. [RFC 5321 §4.1.2](https://www.rfc-editor.org/rfc/rfc5321#section-4.1.2)
and [RFC 5322 §3.4.1](https://www.rfc-editor.org/rfc/rfc5322#section-3.4.1)
define the external mailbox syntax.

Aweb address ownership/current keys come from AWID. DNS/MX and the mail
operator establish the delivery route, not human identity, agent ownership,
signing custody or namespace-controller authority. Revalidate the exact aweb
recipient before intake; a stale mailbox route must not follow an address
reassigned to another DID. The
[identity and messaging contract](identity-messaging-contract.md#authority-boundaries),
lines 25–75, remains binding. Email to an unknown or disabled endpoint gets
no native delivery; the adapter uses its non-disclosing reject/quarantine
policy, not another agent's catch-all inbox.

**Hosted namespaces:** zero setup for the human means the operator provisions
receiving and authorized sending for each enabled namespace. It does not mean
DNS is unnecessary. **BYOT:** email is opt-in; the customer controls the mail
DNS and explicitly authorizes the operator's receiving/sending setup. Do not
replace a customer's existing MX without their decision. A dedicated agents
subdomain is possible only when it is the actual registered namespace; it is
not an email alias silently attached to the parent namespace.

## 2. DNS coverage and sending readiness

Hosted namespaces use one wildcard MX and one matching suffix receipt rule:
for `aweb.ai`, `*.aweb.ai MX 10 inbound-smtp.us-east-1.amazonaws.com` and one
SES receipt rule with [recipient condition `.aweb.ai`](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html).
The attach flow checks the actual MX answer for namespace D before advertising
email as ready. If records at D or below it prevent wildcard synthesis, require
an explicit MX at D pointing to the authorized receiver. This is a provisioning
check, not DNS automation; do not prohibit `_awid`, DKIM or other legitimate
records to preserve a wildcard. BYOT namespaces retain explicit opt-in MX setup
authorized by their customer. Recheck the actual MX answer after namespace DNS
changes.

Why: DNS wildcards synthesize from the closest existing ancestor. A name may
exist without records of its own because it has descendants. Thus adding
`_awid.D` can make D an empty non-terminal and prevent an ancestor wildcard
from supplying D's MX. A record at D can do the same. This follows
[RFC 4592 §§2.2–3.3](https://www.rfc-editor.org/rfc/rfc4592#section-2.2).
It is a closest-encloser rule, not a universal one-label depth limit.
Explicit MX at D handles either case without changing the public address.

Outbound readiness separately requires authorization to send with the exact
`From: name@D`, a stable authorized bounce route, and authenticated identifier
alignment under the deployment's DMARC policy. The consuming operator specifies
and qualifies its DKIM/SPF arrangement before enabling outbound mail. SPF
authorization of an envelope sender is not by itself proof of the visible
From mailbox or H.
[RFC 7489 §3.1](https://www.rfc-editor.org/rfc/rfc7489#section-3.1) defines
identifier alignment. Receipt of email is not evidence that sending is ready.
No particular provider, AWS region or DMARC policy value is required here.
Provider verification and inbound processing must be qualified independently;
this design asserts neither is deployed.

## 3. Human links, admission and author proof

The private personal email link is keyed by H, the ONE human `did:aw`, with
its exact verified mailbox and current consent. Every `(H,S)` channel choice
references that link; team actor IDs never replace H. A human can select email
and another channel simultaneously, or use email in the default set. Apply
[endpoint admission and multi-channel rules](agent-channel-endpoints.md#4-who-may-enter-decision-c)
and the existing [human binding model](human-channel-binding.md#6-email-and-outsider-verification),
lines 207–253.

The receiving service authenticates its provider intake and evaluates the
actual message's sender evidence under an explicitly reviewed mailbox-link
verification policy. A previous mailbox challenge establishes a link, not
proof that every later message bearing that From address was sent by H.
Untrusted headers cannot select an authenticated account or native author.
SPF/DKIM/DMARC results are transport/domain authenticity inputs, not native
Ed25519 signatures or proof of natural personhood. The consumer must state
its accepted evidence and refusal cases before activation; it may not infer
H solely by comparing From, Reply-To or a display name to an account row.

Where the current link, authenticated intake, consent, target access and real
signing custody authorize a native human send, the actual authorized human
key signs as H with `via=email`. Native email reply-in waits until H exists,
is registered/adopted and the host has that legitimate signing authority; a
per-team dashboard/workspace key cannot bridge the wait. A self-custodial
human must supply their own
signed content or use the existing typed bridged-subject path; the host may
not borrow a team actor's key to stand in for H. The
[existing author/custody boundary](human-channels-contract-proposal.md#unlinked-people-and-external-only-agents-a-versus-b),
lines 137–189, remains binding apart from the explicit one-H selector migration.

An unknown or insufficiently authenticated sender is not a native H. Guest
opt-in plus `inbound_mode` cannot turn that message into native verified mail.
The existing guest capability is typed chat/session participation, not native
mail (that contract, lines 205–208). An adapter may use a separately admitted
compatible guest session or refuse/quarantine; it must not invent a native
identity or silently enable guest mail. A working SMTP route does not imply
that guest ingestion has been implemented.

No public human-ID/channel record publishes the human's private mailbox.
Existing `{domain, fingerprint}` privacy rules remain; this profile defines
no fingerprint algorithm or public lookup. Publicly advertising an agent's
derived endpoint address does not publish a human's personal mailbox mapping.
Mailbox change/unverification ends the old link and queued old-route
eligibility; it neither replaces H nor re-parents the agent.

## 4. Thread and reply correlation

The canonical thread key is the aweb `conversation_id`. The email `Subject`
is presentation only. Never parse `Re:`, compare subjects or adopt the pair's
newest conversation to decide where a reply belongs.

Outbound messages use an RFC Message-ID, retained on delivery retries, with a
private mapping to the canonical aweb message ID and exact H/S/delivery
context. Distinct rendered channel copies can have distinct RFC IDs while
mapping to one canonical aweb message. The generating domain is controlled
by the sending operator; no private actor or platform credential is embedded.
For a reply, construct In-Reply-To and References from the mapped parent and
its ancestry, following
[RFC 5322 §3.6.4](https://www.rfc-editor.org/rfc/rfc5322#section-3.6.4).
Keep the recorded mapping rather than guessing from a caller-supplied UUID.

Inbound processing:

1. Authenticate the actual sender/link and exact destination endpoint.
2. Resolve In-Reply-To against that human's authorized delivered-message map.
   If it has no unique parent, resolve References from newest to oldest only
   when the known references identify one authorized conversation. Conflicting
   known conversations or multiple competing parents refuse as ambiguous.
3. Check current H/S participation and delivery permission. A forwarded
   Message-ID is a locator, never a bearer grant or historical read permission.
4. Compose/sign the new native message with that exact conversation ID, or use
   the admitted typed guest session. Preserve original content/signatures;
   no server-side re-threading after signing.
5. With no reply-reference headers, a fresh email starts a new thread with its
   Subject as title. Apply the reviewed new-thread title requirements before
   signing; a missing required title is visible refusal, not pair adoption.
   A message claiming reply references that resolve nowhere is unresolved,
   not silently moved into a new or latest thread.

A reply on Telegram to a copy of aweb message M and a reply by email to a copy
of M both continue M's thread, despite different provider IDs and subjects.
No "answered elsewhere" acknowledgement/cancellation is implied. A transport
retry of the same accepted intake uses the original committed message/result;
it does not create a second logical reply. Source deduplication uses the
adapter's authenticated intake identity, not an arbitrary incoming Message-ID
alone, which is forgeable.

A tokenized Reply-To fallback is **not defined or authorized** by this profile.
If headers are stripped, ask the user to select an authenticated thread or
report unresolved correlation. A future token design needs its own binding,
expiry, disclosure and replay review; no new bearer mechanism is needed here.

## 5. Confidentiality and transport effects

Email delivery is readable by its mail/bridge operators and is never labelled
E2EE. TLS or encrypted wire/storage does not change key custody. Preserve the
original author's proof on the canonical aweb message; a mail-provider or
bridge service signature cannot replace it. Apply the existing export/content
access and attachment limits before copying content, and keep private provider
references out of public signed records. Selecting email is not permission to
expose a self-custodial encrypted message the service cannot decrypt.

Read receipts, delivery success and read state are separate. Accepting SMTP
mail does not mark the canonical aweb message read, prove a human read it, or
acknowledge its other selected channel copies. Failed/unknown delivery follows
the existing durable adapter recovery; it never silently falls back to a
channel outside H's chosen set.

## 6. Additive platform grammar and rollout

This is the profile required by
[human-channel-binding.md:243–253](human-channel-binding.md#6-email-and-outsider-verification).
The implementation proposal adds the exact token `email` to the **shared
closed platform enum**, consistently in every referencing record: native and
binding intents, both owner-proof families, both verified-result families,
bridge admission and platform-scoped delegation. Keep family versions,
existing field sets, signature rules and old platform bytes unchanged.
`via=email` already satisfies the open `platform_kind` grammar; it confers
no new authorization or platform routing by itself.

The current authority is
[human-channels-profile-v1.json](vectors/human-channels-profile-v1.json),
consumed by Python and Go; the generator's shared enum is in
[scripts/freeze_human_channels_profile.py](../scripts/freeze_human_channels_profile.py):29.
This design changes none of those bytes. After approval, add signed positive
email vectors for each affected artifact family and negative signature,
platform/purpose, subject/H, scope, audience, generation and replay neighbours.
Refreeze the public authority deliberately; update compiled grammars, provenance
pins and every actual consumer together. Do not create a second email grammar
or relax unknown-enum validation in released readers.

Before email activation, publish the additive readers/vectors and obtain pins
from all affected producers, verifiers and presentation consumers. Older
closed-enum readers keep accepting their existing platforms and visibly refuse
unsupported email. Preserve old signatures/results; do not translate email to
`telegram`, reserialize a signed payload, or emit to an incapable consumer.
Host adapters separately prove one-H migration, account-link/intake authority,
MX at root/nested/empty-nonterminal namespaces, authorized outbound From,
local-part exactness, two same-subject threads, email/cross-channel replies,
ambiguous/foreign/unresolved references, replay, stopped links, multi-channel
choices and failure isolation. No production write, new schema, vector freeze
or capability activation is part of this design commit.
