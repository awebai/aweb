#!/usr/bin/env node
import { spawn } from "node:child_process";
import { renameSync, writeFileSync } from "node:fs";

const markerPath = process.argv[2];
if (!markerPath) throw new Error("usage: stubborn-process-tree.mjs <marker-path>");

const descendant = spawn(process.execPath, [
  "-e",
  "process.on('SIGTERM', () => {}); process.send('ready'); setInterval(() => {}, 1000)",
], { stdio: ["ignore", "ignore", "ignore", "ipc"] });

await new Promise((resolve, reject) => {
  descendant.once("message", (message) => message === "ready" && resolve());
  descendant.once("error", reject);
  descendant.once("exit", (code, signal) => reject(
    new Error(`descendant exited before readiness: code=${code} signal=${signal}`),
  ));
});

const readyPath = `${markerPath}.${process.pid}.tmp`;
writeFileSync(readyPath, `${JSON.stringify({
  parent_pid: process.pid,
  descendant_pid: descendant.pid,
})}\n`, { mode: 0o600 });
renameSync(readyPath, markerPath);
setInterval(() => {}, 1000);
