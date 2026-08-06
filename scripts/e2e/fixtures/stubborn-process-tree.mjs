#!/usr/bin/env node
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

const markerPath = process.argv[2];
if (!markerPath) throw new Error("usage: stubborn-process-tree.mjs <marker-path>");

const descendant = spawn(process.execPath, [
  "-e",
  "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)",
], { stdio: "ignore" });

writeFileSync(markerPath, `${JSON.stringify({
  parent_pid: process.pid,
  descendant_pid: descendant.pid,
})}\n`, { mode: 0o600 });
setInterval(() => {}, 1000);
