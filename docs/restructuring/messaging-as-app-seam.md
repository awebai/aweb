# Messaging-as-app seam — grounded read (SoT §12.10, milestone 10)

Source: `aw-reviewer` (mapped the channel stack closest), via the cli/ team,
2026-06-16. This is the most code-grounded analysis of the **last, deepest cut** —
splitting `messages`/`chat` semantics off the core transport into first-party
apps (SoT §12 step 10). **Conclusion: converging onto v2 app-auth is the right
direction; no fundamental blocker.** Far-off work; captured now while the read is
fresh so m10 doesn't re-derive it or get it wrong.

## The six checklist items

1. **Two separate auth layers — keep them separate.** *Request auth* (today
   DIDKey + `X-AWEB-DID-AW`) authenticates the HTTP caller; the *signed
   `MessageEnvelope` / E2EE envelope* authenticates the payload to
   recipients/federation. m10 moves **request auth** onto v2 app-auth. The inner
   message/encrypted-envelope signatures **stay payload semantics** — they are
   *not* replaced by app-auth. (Consistent with §3.1: the envelope's own
   signature over subject/conversation is payload-layer.)

2. **Do not just flip `channel-core` to its current `teamAuthHeaders`.** Those
   non-messaging paths use the **compact legacy team auth** (`body_sha256`,
   `team_id`, `timestamp`), *not* the full v2 envelope (`aud`/`method`/`path`/`v`
   + `X-AWEB-Signed-Payload`). Apps must use **v2** — so app hydration either
   calls the Go `aw id request --team-auth` path or a v2 signer is added to
   `channel-core`.

3. **Server already hints the bridge.** `get_messaging_auth` accepts a team-cert
   when `X-AWID-Team-Certificate` is present, else identity auth — so convergence
   is mechanical. But the **app version must REQUIRE app-auth**, not keep
   identity auth as an equal long-term route.

4. **E2EE / local-decrypt is orthogonal, not a blocker.** Metadata-only wake
   holds. Local decrypt (today shells `aw mail show` / `aw chat history`) becomes
   a **messages/chat app hydrator**; the encrypted envelope stays **opaque to
   core transport** (§3.1).

5. **The events stream stays CORE** (team-auth subscriber infra). Future events
   carry app `id`/`type`/resource refs; today's `actionable_mail`/
   `actionable_chat` semantics are the **seam** to generalize, not a blocker
   (this is the same "make the event channel app-generic" work as §12 m3).

6. **Migration watch — global identity vs team-scoped apps.** Identity-auth today
   allows `DID`/`did:aw`-scoped messaging **without forcing a team choice**
   (including an ambiguous global identity). The app contract is **team-scoped**,
   so m10 needs an explicit answer for *"send/read as a global identity with
   multiple or no active team."* Likely resolution: **require an active team /
   app grant for app mutations**, while **core addressability still resolves
   recipients** regardless. This is a real design question to settle at m10, not
   a blocker.

## Net

Convergence onto v2 app-auth is mechanical and correct; the inner
payload/E2EE signatures and the events stream stay where they are; the one
genuine design decision is item 6 (global-identity ↔ team-scoped app mutations).
None of this changes the §3.1 transport definition or the app contract (§7).
