# @awebai/channel-core

Shared aweb channel runtime for host adapters.

This package contains the host-agnostic parts of the aweb channel:

- signed aweb API client
- SSE event stream parsing/reconnect
- mail/chat fetch and read/ack helpers
- sender signature verification and trust normalization
- channel event dispatch into semantic awakenings

Host packages such as `@awebai/claude-channel` and `@awebai/pi-extension` map those awakenings to their own runtime APIs.
