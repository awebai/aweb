---
type: Lesson
title: A legacy verification status names a format, not a trust result
description: verified_legacy only says the signed envelope carries no conversation claim; when the registry, TOFU-pin and custody checks ran only for verified, leaving out one signed field let another key pass as a pinned sender, so every envelope format runs the same trust checks and keeps its format label only when they pass. On a handed-back branch, not yet on main.
tags: [lesson, verification, trust, tofu, chat, compatibility]
timestamp: 2026-11-21
---

`verified_legacy` means that a message's signature is good and its signed
payload has no `conversation_id`. It says nothing about whether the signing
key belongs to the named sender. In the Go receive path and in channel-core
the sender-trust checks (the registry stable-identity check, the TOFU pin and
the custody/meta check) ran only for `verified`. A key that was not the
sender's could therefore sign a message in a pinned sender's name, omit the
conversation claim, and be displayed as that sender with no warning tag. The
gap was present since aw-v1.19.0 and channel-v1.4.1.

The weaker status was reachable by the attacker's own choice of envelope
format. Any status the display treats as trusted must reach every check that
`verified` reaches, or the "compatibility" status becomes the way around
verification.

# The rule

- The sender-trust owner runs the checks for a legacy-format message exactly
  as for `verified`. A passing result maps back to `verified_legacy`, so the
  format stays visible. A failing check gives the same outcome as it would
  for a current-format message.
- Go and TypeScript share one helper shape for this (`checkedAsVerified`), and
  the shared vector `tofu-v2` carries legacy-format cases so both languages
  must reach the same verdict.

# How to apply

When adding a trusted status, or gating any check on a status, find every
`status != Verified`-style gate and decide for each whether the new status
must pass through it. Add a parity case that shows the weaker format reaches
the same verdict as the current one. The parity tests are the elimination
route; this lesson records why they exist so they are not "simplified" away.

Related: [a message read from a conversation is bound to the conversation
asked for](/aweb-protocol-expert/decisions/a-read-message-is-bound-to-the-requested-conversation.md)
closes the replay half of the same review finding.

Status: fixed on branch `agents/aweb-protocol-expert-chat-verify-adje3`
(commit 573552b2ff, head 5e758c7bb5, handed back 2026-11-21); not yet on
main or released. The parity tests are red without the fix in Go and TS
(source-reported, mutation-checked).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/legacy-status-is-a-format-not-a-trust-result.md. Commit 573552b2ff and `checkedAsVerified` verified on the branch.
