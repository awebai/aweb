import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { DeliveryStore } from "../dist/channel.js";

const helperPath = fileURLToPath(new URL("./helpers/delivery_store_process_writer.mjs", import.meta.url));

async function waitForFiles(paths) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const ready = await Promise.all(paths.map(async (candidate) => {
      try {
        await access(candidate);
        return true;
      } catch {
        return false;
      }
    }));
    if (ready.every(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("delivery-store subprocesses did not reach the barrier");
}

function childExit(child, stderr) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`delivery-store subprocess exited ${code ?? signal}: ${stderr()}`));
    });
  });
}

test("compiled DeliveryStore keeps repeated and distinct marks from 16 barrier-released processes", { timeout: 45_000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "delivery-process-"));
  const storePath = join(dir, "channel-delivered-ids.json");
  const releasePath = join(dir, "release");
  await writeFile(storePath, "{}\n", "utf8");

  const processes = Array.from({ length: 16 }, (_, index) => {
    const readyPath = join(dir, `ready-${index}`);
    const child = spawn(
      process.execPath,
      [helperPath, storePath, readyPath, releasePath, "shared-msg", `process-msg-${index}`],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    return { child, readyPath, exited: childExit(child, () => stderr) };
  });

  try {
    await waitForFiles(processes.map(({ readyPath }) => readyPath));
    const release = await open(releasePath, "wx", 0o600);
    await release.close();
    await Promise.all(processes.map(({ exited }) => exited));

    const reloaded = await DeliveryStore.load(storePath);
    assert.equal(reloaded.has("shared-msg"), true, "shared-msg");
    for (let index = 0; index < processes.length; index += 1) {
      assert.equal(reloaded.has(`process-msg-${index}`), true, `process-msg-${index}`);
    }
  } finally {
    for (const { child } of processes) {
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
    await rm(dir, { recursive: true, force: true });
  }
});
