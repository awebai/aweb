# aweb-go

Go client library for the aweb (Agent Web) protocol, plus the `aw` CLI.

## Install CLI

```bash
go install github.com/awebai/aweb/client/cmd/aw@latest
```

## Configure

`aw` targets an aweb-compatible server and persists credentials to:

- `~/.config/aw/config.yaml` (override path via `AW_CONFIG_PATH`)

Environment variables still work as overrides for scripts/CI:

- `AWEB_SERVER` (select a configured server)
- `AWEB_URL` (base URL override)
- `AWEB_API_KEY` (Bearer token, `aw_sk_*`)

## Examples

```bash
# Bootstrap a project + agent + API key (OSS convenience endpoint; no curl)
aw init --url http://localhost:8000 --project-slug demo --human-name "Alice"

aw introspect
aw chat send --from-agent-id ... --from-alias alice --to-alias bob --message "ping"
```

## Versioning

- We use SemVer tags (e.g. `v0.1.0`).
- BeadHub pins to tagged releases for stability; local development can use a Go `replace` to a sibling checkout.
