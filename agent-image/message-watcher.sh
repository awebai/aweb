#!/usr/bin/env bash
set -euo pipefail

# message-watcher.sh — Ordis control-plane message loop
#
# Polls BeadHub for pending chat messages and kicks claude -p to process them.
# Designed to run as the orchestrator pod entrypoint.
#
# Required env vars:
#   DISCORD_ORDIS_WEBHOOK_URL — Discord webhook for #ordis channel
#   CLAUDE_CODE_OAUTH_TOKEN   — Claude Code auth token (from claude setup-token)
#
# Optional:
#   POLL_INTERVAL — seconds between polls (default: 5)

POLL_INTERVAL="${POLL_INTERVAL:-5}"

echo "[message-watcher] Initializing ordis for control-plane project..."
bdh :init --alias ordis --role coordinator

# Post "online" to Discord #ordis channel
if [ -n "${DISCORD_ORDIS_WEBHOOK_URL:-}" ]; then
  curl -sf -H "Content-Type: application/json" \
    -d '{"username":"🎯 ordis","content":"Hey, I\u0027m up and listening — what are we working on? 👋"}' \
    "$DISCORD_ORDIS_WEBHOOK_URL" >/dev/null 2>&1 || \
    echo "[message-watcher] Warning: failed to post online message to Discord"
fi

echo "[message-watcher] Entering message watch loop (poll every ${POLL_INTERVAL}s)..."

while true; do
  pending=$(bdh :aweb chat pending 2>/dev/null || echo "")

  if [ -n "$pending" ] && ! echo "$pending" | grep -qi "no pending"; then
    echo "[message-watcher] Pending messages detected — kicking claude -p"
    claude -p "You have pending messages. Run bdh :aweb chat pending and respond to all conversations." \
      --dangerously-skip-permissions 2>&1 || \
      echo "[message-watcher] Warning: claude -p exited with non-zero status"
  fi

  sleep "$POLL_INTERVAL"
done
