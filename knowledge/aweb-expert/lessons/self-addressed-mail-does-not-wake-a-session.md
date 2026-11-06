---
type: Lesson
title: Self-addressed mail does not wake a session
description: The aw wake resolvers and the channel deliberately skip self-authored mail and chat, so mailing yourself when a queued job finishes never resumes you; keep the job's exact head and result artifacts so the result can be recovered on the next real wake.
tags: [lesson, messaging, wake, channel, coordination]
timestamp: 2026-10-25
---

A seat that queued long test jobs had each job mail itself on completion,
expecting to be woken. On four occasions the self-mail was recorded within
seconds of the job ending and the seat resumed only when unrelated mail arrived,
in one case more than three hours later. The seat first recorded the cause as a
hypothesis; the source settles it. Wake resolution skips self-authored messages
by design, in the CLI dispatcher and in the channel, for mail and for chat.

# How to apply

- Do not use self-addressed mail or chat as a continuation mechanism; a
  successful send proves delivery, not a wake.
- No automatic job-triggered wake was observed to work for this purpose. What
  worked was recovery: on the next real wake, read the retained tool session,
  log and exit files at the job's exact head instead of rerunning or
  misreporting an unfinished test.
- Track work by its done signal, as in
  [drive coordination to done](/aweb-expert/lessons/drive-coordination-to-done.md),
  and make that signal something a real wake will surface.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-naapp-approvals` (note
`self-mail-is-not-a-verified-continuation.md`, updated by the seat after review;
reply 213bd556). Verified on main f8f627fb9:
`TestResolveMailWakeSkipsSelfAuthoredMessageByAddress` and the chat
equivalents in `cli/go/cmd/aw/run_dispatch_test.go`, and "skips self-authored
mail by concrete address" in `channel/test/dispatch.test.ts`.
