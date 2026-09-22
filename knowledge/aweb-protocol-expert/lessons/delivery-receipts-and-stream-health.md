---
type: Lesson
title: Delivery receipts and stream health in channel adapters
description: Treat an adapter's wake completion as a delivery receipt only where the host defines a real acceptance boundary; a fire-and-forget transport send is not one, so honest visible-unread mail beats acknowledged-but-unseen mail; schedule event lanes independently and declare stream health only after live evidence.
tags: [lesson, channel, delivery, sse, runtime-integration]
timestamp: 2026-09-21
---

Recorded by the OSS developer role while building the channel runtime
integrations (undated); verified as the current design on 2026-09-21: the
channel-core event stream uses bounded backoff on early failures, and the
channel keeps delivered-identifier state to suppress replay. Re-verify the
specific hook names in the current adapter before relying on them.

# The rules

- An adapter's wake completion counts as delivery only when the host API has a
  real model or session-queue acceptance boundary. Hold ordinary wake delivery
  while a turn is active, flush at the turn boundary, and resolve only after the
  host accepts the injection; reject queued and in-flight promises on shutdown
  so late settlement cannot acknowledge source mail.
- A fire-and-forget transport notification carries no host acknowledgement.
  There, local delivered-identifier state suppresses reconnect replay while
  server mail stays unread until the agent replies or explicitly acknowledges.
  Honest visible-unread mail is preferable to acked-but-unseen mail.
- Do not fix delivery ordering by blocking the whole stream consumer: schedule
  independent lanes (mail serially, chat per session) so a pending mid-turn mail
  cannot block control signals or unrelated chat.
- A response opening is not evidence the stream is healthy; proxies return
  success and immediately end. Declare initial health or recovery only after the
  first parsed event, and back off early end-of-stream and read failures, or
  flapping responses tight-spin, oscillate notices and queue false catch-up
  wakes.
