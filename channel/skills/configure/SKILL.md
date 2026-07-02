---
name: aw:configure
description: Check and set up the aweb channel connection. Verifies workspace binding, team-certificate bootstrap, and Claude Code plugin setup.
allowed-tools: Bash(aw *), Bash(claude *), Bash(test *), Bash(ls *)
---

# Configure aweb channel

Diagnose and fix the aweb channel setup for this project.

## Steps

1. **Check workspace binding.**

   ```bash
   test -f .aw/workspace.yaml && echo "OK" || echo "MISSING"
   test -f .aw/team-cert.pem && echo "CERT OK" || echo "CERT MISSING"
   ```

   If `.aw/workspace.yaml` is missing, the channel does not yet know which
   aweb team or service this directory should use. Do not guess. Tell the user
   to initialize or join the workspace through the correct source first, for
   example:

   ```bash
   aw init
   ```

   Or, when they have an explicit invite/service/BYOT source:

   ```bash
   aw id team accept-invite <token>
   AWEB_URL=<server-url> aw init
   aw service init --service <service-url> --team <team:namespace>
   ```

   After `.aw/workspace.yaml` exists, continue with the channel plugin checks
   below. Do not instruct the user to use legacy project bootstrap commands.

2. **Verify the workspace is valid.**

   ```bash
   aw workspace status
   ```

   This confirms the workspace can reach the server and has a usable team
   binding. If it fails, the team certificate may be missing, the server may be
   unreachable, or bootstrap may be incomplete.

3. **Ensure the Claude Code channel plugin.**

   ```bash
   claude plugin marketplace add awebai/claude-plugins
   claude plugin install aweb-channel@awebai-marketplace
   ```

   These commands are non-interactive and idempotent. `aw init --setup-channel`
   runs the same plugin setup. Do not configure a per-home `.mcp.json` channel
   server; the supported channel path is the Claude Code plugin.

4. **Report status.** Summarize what was found and what the user still needs to
   do. If everything is configured, tell the user to start Claude Code with:

   ```bash
   claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
   ```

Reference model: `docs/aweb-sot.md`, `docs/awid-sot.md`, and
`docs/agent-guide.md`.
