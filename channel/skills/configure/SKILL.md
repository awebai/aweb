---
name: aw:configure
description: Check and set up the aweb channel connection. Verifies workspace binding, credentials, and MCP server configuration.
allowed-tools: Bash(aw *), Bash(cat *), Bash(test *), Bash(ls *)
---

# Configure aweb channel

Diagnose and fix the aweb channel setup for this project.

## Steps

1. **Check workspace binding.**

   ```bash
   test -f .aw/workspace.yaml && echo "OK" || echo "MISSING"
   ```

   If `.aw/workspace.yaml` is missing, the workspace has not been initialized.
   Tell the user to run:

   ```bash
   aw init
   ```

   This requires credentials (`~/.config/aw/config.yaml`). If the user doesn't
   have credentials yet, they need to either:
   - Create a project: `aw project create --server-url https://app.aweb.ai`
   - Connect with an API key: `AWEB_URL=https://app.aweb.ai/api AWEB_API_KEY=aw_sk_... aw connect`

   Stop here until the user has run `aw init` successfully.

2. **Verify the workspace is valid.**

   ```bash
   aw workspace status
   ```

   This confirms the workspace can reach the server. If it fails, the
   credentials may be expired or the server may be unreachable.

3. **Check channel MCP configuration.**

   ```bash
   cat .mcp.json 2>/dev/null || echo "MISSING"
   ```

   Look for an `mcpServers.aweb` entry. If it's missing, tell the user to run:

   ```bash
   aw init --setup-channel
   ```

   Or add the entry manually to `.mcp.json`:

   ```json
   {
     "mcpServers": {
       "aweb": {
         "command": "npx",
         "args": ["@awebai/claude-channel"],
         "cwd": "<project directory>"
       }
     }
   }
   ```

   The `cwd` must point to the directory containing `.aw/workspace.yaml`.

4. **Report status.** Summarize what was found and any actions the user needs to take. If everything is configured, tell the user to start Claude Code with:

   ```bash
   claude --dangerously-load-development-channels server:aweb
   ```
