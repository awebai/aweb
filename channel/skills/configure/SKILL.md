---
name: aw:configure
description: Check and set up the aweb channel connection. Verifies workspace binding, team-certificate bootstrap, and MCP server configuration.
allowed-tools: Bash(aw *), Bash(cat *), Bash(test *), Bash(ls *)
---

# Configure aweb channel

Diagnose and fix the aweb channel setup for this project.

## Steps

1. **Check workspace binding.**

   ```bash
   test -f .aw/workspace.yaml && echo "OK" || echo "MISSING"
   test -f .aw/team-cert.pem && echo "CERT OK" || echo "CERT MISSING"
   ```

   If `.aw/workspace.yaml` is missing, the workspace is not initialized yet.
   Tell the user to run:

   ```bash
   aw run claude
   ```

   Or use the explicit invite flow:

   ```bash
   aw id team accept-invite <token>
   AWEB_URL=<server-url> aw init
   ```

   Do not instruct the user to use legacy project bootstrap commands.

2. **Verify the workspace is valid.**

   ```bash
   aw workspace status
   ```

   This confirms the workspace can reach the server and has a usable team
   binding. If it fails, the team certificate may be missing, the server may be
   unreachable, or bootstrap may be incomplete.

3. **Check channel MCP configuration.**

   ```bash
   cat .mcp.json 2>/dev/null || echo "MISSING"
   ```

   Look for an `mcpServers.aweb` entry. If it is missing, tell the user to run:

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

4. **Report status.** Summarize what was found and what the user still needs to
   do. If everything is configured, tell the user to start Claude Code with:

   ```bash
   claude --dangerously-load-development-channels server:aweb
   ```

Reference model: `docs/aweb-sot.md`, `docs/awid-sot.md`, and
`docs/agent-guide.txt`.
