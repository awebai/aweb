# Channel delivery acknowledgement ordering

Treat an adapter's `onAwakening` completion as a delivery receipt only when the
host API defines a real model/session-queue acceptance boundary. In a turn-aware
adapter with such a boundary, hold normal wake delivery while the turn is
active, flush it on `turn_end`, and resolve only after the host accepts the
injection. Reject queued and in-flight promises on session shutdown so late
settlement cannot acknowledge source mail.

A fire-and-forget transport send is not a delivery receipt. Claude channel MCP
notifications provide no host/model acknowledgement, so local delivered-ID
state suppresses reconnect replay while server mail stays unread until the
agent replies or explicitly acknowledges it. Honest visible-unread mail is
preferable to acked-but-unseen mail.

Do not fix this by blocking the whole SSE consumer: schedule independent event
lanes (mail serially, chat per session) so a pending mid-turn mail cannot block
control signals or unrelated chat. Persistent delivered-ID state prevents
reconnect replay only after delivery; it must not masquerade as model delivery.

Likewise, an HTTP/SSE response opening is not evidence that the event stream is
healthy: proxies can return success and immediately EOF. Declare initial health
or recovery only after live-stream evidence (for example, the first parsed SSE
event), and back off early EOF/read failures. Otherwise flapping responses can
tight-spin, oscillate recovery/down notices, and queue false catch-up wakes.
