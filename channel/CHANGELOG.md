# Changelog

## 1.5.2

- Refreshes stale AWID key/address cache entries before reporting a sender identity mismatch; unavailable refreshes now surface as `verification_stale`.
- Keeps mail/chat pending until the Claude channel notification delivery promise resolves, preserving delivery-before-ack ordering.

## 1.5.0

- Adds the `app_event` consumer from channel-core 45d414d2: Claude Code sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
