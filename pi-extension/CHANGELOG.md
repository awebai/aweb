# Changelog

## 0.2.2

- Holds normal wake delivery received mid-turn until `turn_end`, and acknowledges source mail/chat only after Pi accepts the injection.
- Refreshes stale AWID key/address cache entries before reporting a sender identity mismatch; unavailable refreshes now surface as `verification_stale`.

## 0.2.0

- Adds the `app_event` consumer from channel-core 45d414d2: Pi sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
