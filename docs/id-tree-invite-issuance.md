# Team invites and ID-parent issuance

Design for aweb-acmj.24, implementing Juan's 2026-10-30 invite-issuer ruling
(responsibility e61b0205 / 13db580c). This supersedes the proposed
“decoupled-by-design” disposition of `CLI.INVITE.LOCAL`.

A chained agent invites another agent, but today's team acceptance creates a
chainless key: `aw who` loses the inviter's responsible human. Compose the
existing team invitation and [child exchange](id-certificates.md#self-custodial-child-requests-and-re-sign-transport)
so acceptance completes both operations. Their authorities remain separate:
the team controller signs membership; the actual inviting identity signs the
ID certificate ([§1](id-certificates.md#1-what-the-tree-proves)).

## Smallest flow

1. At invite creation, select the actual inviting identity and check its
   current chain. Create its existing `self_custodial`, `kind=agent` child
   invitation. Add an optional private linkage in the local `TeamInvite`:
   that invitation ID, actual parent/domain and issuer-record location. Fix
   the purpose as agent spawn; retain/display it with the issuing identity
   and verified human, or verified `no_human`. These are invitation metadata,
   not new certificate fields. Never infer the parent from the team key.
2. After acceptance prepares the recipient's key, compose the existing
   request → receive → agent approve → import functions against that linked
   child invitation. Its first request binds the exact child ID/key; the
   issuer rechecks current authority and records issuance before release.
   Agent signing needs no human prompt. A local child carries the installed
   chain; an unenrolled global child registers with its own key proof and
   the same child invitation ID. A global child needs a registered parent;
   refuse rather than implicitly enroll its inviter. No new registry route, signing family or
   approval protocol is needed.
3. Keep the invitation linkage until completion. Reuse existing pending
   request/response records for retry; never mint another child or sign a
   different certificate on retry. Membership may already have completed:
   report ID enrollment as pending/failed until installation/registration
   succeeds, and resume that exact exchange. Current local team acceptance
   already needs the issuer's private local records. If those records are on
   another machine, use the existing explicit file exchange; add no daemon.

A genuinely chainless inviter retains the existing human-less path and
reports `unknown`, without a guessed human or parent signature. A revoked,
stale or unavailable previously chained issuer cannot silently fall back to
that path. Reuse the production client's evidence through 60 seconds inclusive;
refresh older evidence once, and refuse issuance if that refresh fails. Membership alone never supplies issuance authority.

`accept-invite --global` reuses an existing global identity. Apply initial ID
issuance only when it is authoritatively unenrolled. Preserve an existing
chain on a membership-only join; changing its parent needs the explicit
[re-parent procedure](id-certificates.md#2-certificate-and-exact-bytes),
tracked by acmj.20. Cross-domain membership does not authorize a cross-domain
ID-parent link. Existing tokens/member certificates remain readable; an old
client completing only membership cannot claim the new ancestry guarantee.

## One real journey

Extend the existing CoreDNS row: human H → inviting agent P; P creates a
local team invite; recipient accepts; immediately assert `aw who` has parent
P and nearest human H, with the exact chain and purpose retained. Public Go
and Python outsiders verify it. Repeat the same row for an unenrolled global
recipient, proving subject registration; retain the already-chained global
join as the chain-preservation control. A chainless-inviter control stays
`unknown`; a revoked-issuer control issues nothing. Use the real CLI, DNS,
AWID and existing exchange, without constructing a certificate in the test.
