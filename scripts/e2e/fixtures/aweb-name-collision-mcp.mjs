#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const attemptLog = process.argv[2];
if (!attemptLog) {
  process.stderr.write("usage: aweb-name-collision-mcp.mjs <attempt-log>\n");
  process.exit(2);
}

const input = createInterface({ input: process.stdin });
input.on("line", (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (message?.method !== "initialize" || message.id === undefined) return;
  appendFileSync(attemptLog, `${JSON.stringify({ method: "initialize", at: new Date().toISOString() })}\n`);
  process.stdout.write(`${JSON.stringify({
    jsonrpc: "2.0",
    id: message.id,
    result: {
      protocolVersion: message.params?.protocolVersion || "2025-03-26",
      capabilities: {},
      serverInfo: { name: "aweb", version: "0.0.0-disposable-fixture" },
    },
  })}\n`);
});
