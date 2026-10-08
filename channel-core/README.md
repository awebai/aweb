# @awebai/channel-core

Shared aweb channel runtime for host adapters.

This package contains the host-agnostic parts of the aweb channel:

- signed aweb API client
- SSE event stream parsing/reconnect
- mail/chat fetch and read/ack helpers
- sender signature verification and trust normalization
- channel event dispatch into semantic awakenings

Host packages such as `@awebai/claude-channel` and `@awebai/pi-extension` map those awakenings to their own runtime APIs.

## Encrypted delivery trust

For encrypted v2 mail and chat, the local `aw` decrypt provider authenticates
plaintext using AEAD and the inner-header mirror. Channel Core independently
verifies the returned v2 envelope signature and binds it to the fetched envelope,
message/thread, sender and recipient before passing signed identity fields
through the usual pin, rotation and registry-checkpoint checks. CLI trust status
strings are not imported. Decrypt errors keep the existing failure notification;
missing or invalid proof cannot produce a verified awakening.

The proof fields are present in `aw` 1.36.26 and 1.36.27 JSON output. Mail carries
`conversation_id` per message; chat carries `session_id` on the history result.
Providers without the required envelope and identity fields remain unverified.
The TypeScript side does not acquire decryption keys or replace grant custody.
