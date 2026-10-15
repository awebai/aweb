# Agent health clients

The [agent health contract](agent-health.md) defines publisher authority and
the signed document. CLI support is prepared for **aw 1.36.38**; receive receipts
are prepared for **Claude channel 1.7.17** and **Pi 0.3.15**. These version floors
take effect when those releases are published. They also require a server with
the agent-health routes.

## Designate and publish with aw

These commands use the selected identity home (including `--identity-home` and
`AWEB_IDENTITY_HOME`), its root signing key and team certificate. They authenticate
with team-auth v2. A grant home cannot designate or publish; use its resident
custody root. They do not renew encryption keys or check for CLI updates.

```sh
aw status-host set --host-did did:key:z... --json
aw status-host show --json
aw status-host clear --json
aw status publish --alias alice --document - --json < status.json
```

`--document` accepts a file path or `-` for stdin. The publisher validates the
document against the frozen `agent-status-v1` rules. aw parses one JSON object,
canonicalizes it (sorted keys, compact UTF-8, no ASCII escaping), and signs the
canonical bytes without adding a timestamp. It refuses before signing if
`publisher_did` differs from the loaded key's `did:key`. The server verifies the
document, team, subject, publisher authority, sequence and publish rate.

Every `--json` invocation writes one JSON object to stdout. Success adds
`"ok": true` and the HTTP `status` to the server object. A refusal has `ok: false`,
HTTP `status`, `code`, the server's `message`, and `retry_after` (seconds or null).
The server's `detail` string has the form `code: message`; aw splits at the first
`: ` and preserves the message. Uncoded 401/403 auth refusals use `auth`;
uncoded 422 validation refusals use `request_shape`. Their `message` preserves
the raw detail, including validation lists. Other uncoded HTTP errors use `http`.
Transport failures use `code: "transport"` and
`status: null`; other local failures use `code: "local"` and `status: null`.
Exit codes are 0 for success, 3 for a server refusal, and 1 for other failures.
Diagnostics may also appear on stderr.

For offline interoperability tests:

```sh
aw status publish --alias alice --document - --print-signed < status.json
```

This makes no network requests and prints only `signed_payload` (base64url
without padding) and `signature` (standard base64 without padding). It normally
uses the selected root key. Tests may instead set `AW_AGENT_STATUS_TEST_SEED_HEX`
to a 32-byte hex seed, as in the frozen vector. A nonempty test-seed variable is
refused for online publishing. Neither mode prints private key material.

## Receive receipts

When native channel delivery is enabled, both adapters write
`<resolved identity directory>/receive/stream.json`. The default directory is
`<workdir>/.aw`; an explicit identity home already names the credential directory
and does not acquire another `.aw` suffix.

```json
{"v":1,"kind":"pi-extension","did":"did:key:z...","stable_id":"did:aw:...","pid":1234,"opened_at":"2026-10-15T06:00:00.000Z","heartbeat_at":"2026-10-15T06:00:30.000Z"}
```

`kind` is `claude-channel` or `pi-extension`. `did` is the resident signing
`did:key` (including for grant seats); `stable_id` is its `did:aw` when present
and is otherwise omitted. `pid` is the adapter process holding the stream.
Timestamps are UTC. `opened_at` identifies the current connection attempt;
`heartbeat_at` records a successful server read, including SSE keepalive comments.

The first successful read creates the file. Later reads refresh it at most
once every 30 seconds; a timer alone never refreshes it. Writes use a private
temporary file and atomic rename with mode 0600. Stream close, disconnect and
clean adapter shutdown remove the current stream's receipt before reconnect
backoff; an old process closing cannot remove a replacement process's receipt.
With `AWEB_DELIVERY=session`, the adapters open no stream and write no receipt.

A host publisher checks that the receipt's identity matches (`stable_id` for
global identities, `did` for local identities), its PID is alive, and its last
read is within 90 seconds. A receipt is local evidence of receive, not a signed
artifact or an authorization credential. Crashes may leave a stale file, so file
existence alone proves nothing.
