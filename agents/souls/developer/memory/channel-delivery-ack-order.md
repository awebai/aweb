# Channel delivery acknowledgement ordering

A channel adapter's `onAwakening` completion is a delivery receipt, not a queue
receipt. Source mail/chat must remain unread until that promise resolves after
the host accepts model/session injection. In a turn-aware adapter, hold normal
wake delivery while the turn is active, flush it on `turn_end`, and resolve the
promise only after the host send succeeds. Reject pending promises on session
shutdown so the source remains visible.

Do not fix this by blocking the whole SSE consumer: schedule independent event
lanes (mail serially, chat per session) so a pending mid-turn mail cannot block
control signals or unrelated chat. Persistent delivered-ID state prevents
reconnect replay only after delivery; it must not masquerade as model delivery.
