#!/usr/bin/env node
// Spawn the aweb-channel MCP server as a subprocess, perform the minimal
// MCP initialize handshake over stdio, and capture every
// notifications/claude/channel notification it emits during a fixed window.
//
// Usage: node capture-channel-events.mjs <channel-dist-path> <capture-seconds>
//
// Output: one JSON object per line on stdout, each {meta, content} from
// the channel notification. stderr from the channel is forwarded.
//
// The script is intentionally MCP-SDK-free: it speaks just enough JSON-RPC
// over the channel's stdio transport to coax notifications out, then prints
// each captured one as JSON.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const channelPath = process.argv[2];
const captureSeconds = Number(process.argv[3] || 30);

if (!channelPath || !Number.isFinite(captureSeconds)) {
  process.stderr.write(
    "usage: node capture-channel-events.mjs <channel-dist-path> <seconds>\n",
  );
  process.exit(2);
}

const proc = spawn("node", [channelPath], {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
});

const rl = createInterface({ input: proc.stdout });

rl.on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg && msg.method === "notifications/claude/channel" && msg.params) {
    process.stdout.write(JSON.stringify(msg.params) + "\n");
  }
});

const writeMessage = (obj) => {
  proc.stdin.write(JSON.stringify(obj) + "\n");
};

writeMessage({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2024-11-05",
    capabilities: { experimental: { "claude/channel": {} } },
    clientInfo: { name: "amy-capture", version: "0.0.1" },
  },
});

writeMessage({
  jsonrpc: "2.0",
  method: "notifications/initialized",
});

const timer = setTimeout(() => {
  // Give the channel a brief grace period to flush + exit cleanly on
  // SIGTERM, then SIGKILL if it's still alive. The channel's MCP loop
  // can ignore SIGTERM in some configurations; SIGKILL guarantees the
  // capture window terminates so the bash `wait` doesn't hang.
  proc.kill("SIGTERM");
  setTimeout(() => {
    try { proc.kill("SIGKILL"); } catch {}
  }, 2000);
}, captureSeconds * 1000);

proc.on("exit", () => {
  clearTimeout(timer);
  process.exit(0);
});

// Hard outer safety: if neither SIGTERM nor SIGKILL produce an exit
// event within (captureSeconds + 10) seconds, bail with a non-zero
// status so bash `wait` returns and the phase can continue/fail.
setTimeout(() => {
  try { proc.kill("SIGKILL"); } catch {}
  process.stderr.write("capture-channel-events: hard timeout, exiting\n");
  process.exit(2);
}, (captureSeconds + 10) * 1000);

const cleanup = (sig) => {
  proc.kill(sig);
};
process.on("SIGINT", () => cleanup("SIGINT"));
process.on("SIGTERM", () => cleanup("SIGTERM"));
