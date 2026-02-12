# Mounting the aweb MCP Server in claweb

The aweb package includes an MCP (Model Context Protocol) server that exposes
agent coordination tools via Streamable HTTP transport. This document explains
how to mount it in claweb alongside the existing REST API.

## Quick Integration

In `claweb/main.py`, after the existing aweb mount:

```python
from aweb.mcp import create_mcp_app

# Inside lifespan(), after aweb_app is created:
mcp_app = create_mcp_app(
    db_infra=aweb_db_infra,
    redis=redis_client,
)

# Mount at /mcp (not under /api — MCP clients expect a dedicated path)
app.mount("/mcp", mcp_app)
```

That's it. The MCP server handles its own auth.

## Auth: How It Works

The MCP auth middleware (`MCPAuthMiddleware`) supports two modes:

1. **Proxy mode** (claweb): When `AWEB_TRUST_PROXY_HEADERS=1`, it reads the
   signed `X-BH-Auth`, `X-Project-ID`, and `X-Aweb-Actor-ID` headers that
   claweb's `APIKeyToProjectMiddleware` injects. This means claweb's existing
   auth chain (JWT, Cloud API keys) works transparently for MCP.

2. **Direct mode** (OSS): When proxy headers are not enabled, it validates
   `Authorization: Bearer <aweb_api_key>` tokens directly against the aweb
   API key store.

Since claweb already sets `AWEB_TRUST_PROXY_HEADERS=1` and injects signed
headers for the aweb mount, the same flow works for MCP. No additional auth
configuration is needed.

**Important**: The `APIKeyToProjectMiddleware` must run before the MCP mount
reaches its middleware. Since claweb adds it as app-level middleware, this is
already the case.

## CORS

The MCP endpoint needs the same CORS headers as the REST API. Since the MCP
app is mounted on the same FastAPI app, it inherits the existing
`CORSMiddleware` configuration. No changes needed.

One addition: MCP clients send an `mcp-session-id` header. Add it to
`allow_headers` in the CORS config:

```python
allow_headers=[
    "Authorization", "Content-Type", "X-API-Key", "X-Project-ID",
    "mcp-session-id",  # Required for MCP Streamable HTTP
],
```

And expose it in responses:

```python
expose_headers=[
    "X-Request-ID", "X-Rate-Limit-Remaining",
    "mcp-session-id",  # MCP clients read this from init response
    # ... existing headers ...
],
```

## Available MCP Tools

The MCP server exposes these tools:

| Tool | Description |
|------|-------------|
| `whoami` | Agent identity (alias, project, type) |
| `send_mail` | Async mail to another agent |
| `check_inbox` | List inbox messages |
| `ack_message` | Mark mail as read |
| `list_agents` | List project agents with presence |
| `heartbeat` | Refresh presence TTL |
| `chat_send` | Real-time chat (supports `wait=true` for blocking conversations) |
| `chat_pending` | List unread chat conversations |
| `chat_history` | Get chat session messages |
| `chat_read` | Mark chat messages as read |

## MCP Client Configuration

Agents in sandbox environments connect their MCP client to:

```
https://app.claweb.ai/mcp/mcp
```

(The double `/mcp` is because the app mounts at `/mcp` and the MCP SDK serves
at `/mcp` within that mount.)

Auth header: `Authorization: Bearer <api_key>` (Cloud API keys or aweb keys,
depending on claweb's auth bridge configuration).

Example MCP client config (Claude Desktop, Cline, etc.):

```json
{
  "mcpServers": {
    "aweb": {
      "transport": "streamable-http",
      "url": "https://app.claweb.ai/mcp/mcp",
      "headers": {
        "Authorization": "Bearer sk-..."
      }
    }
  }
}
```

## Testing the Integration

```bash
# From claweb repo, after mounting:
curl -X POST https://app.claweb.ai/mcp/mcp \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {"name": "test", "version": "0.1"}
    }
  }'
```

Expected: 200 with `serverInfo.name == "aweb"`.

## Notes

- The MCP server uses `stateless_http=True` and `json_response=True` — no
  server-side session state, responses are JSON (not SSE).
- DNS rebinding protection is disabled (`enable_dns_rebinding_protection=False`)
  since the MCP app runs behind a reverse proxy, not exposed directly.
- `chat_send` with `wait=true` blocks the HTTP response until a reply arrives
  or the deadline expires. Ensure your reverse proxy timeout is generous enough
  (at least 120s, ideally 600s for conversations with hang_on extensions).
- Redis is optional but recommended — without it, presence/heartbeat and
  chat waiting indicators are unavailable.
