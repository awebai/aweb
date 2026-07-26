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

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

async function waitForExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processAlive(pid)) return Date.now();
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return null;
}

// A parent killed with SIGKILL runs no handler, so nothing can write the
// release file and nothing can clean up on its behalf. The helper has to
// notice on its own, or it waits forever: 16 of them survived 23 hours this
// way after their runner was retired.
test("helper exits when its parent dies without releasing", { timeout: 30_000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "delivery-orphan-"));
  const storePath = join(dir, "channel-delivered-ids.json");
  const readyPath = join(dir, "ready-orphan");
  const releasePath = join(dir, "release");
  await writeFile(storePath, "{}\n", "utf8");

  const parentPath = join(dir, "parent.mjs");
  await writeFile(
    parentPath,
    [
      'import { spawn } from "node:child_process";',
      "const [helper, storePath, readyPath, releasePath] = process.argv.slice(2);",
      'const child = spawn(process.execPath, [helper, storePath, readyPath, releasePath, "orphan-msg"], { stdio: "ignore" });',
      'process.stdout.write(String(child.pid) + "\\n");',
      "setInterval(() => {}, 60_000);",
    ].join("\n"),
    "utf8",
  );

  const parent = spawn(process.execPath, [parentPath, helperPath, storePath, readyPath, releasePath], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  let helperPid = 0;
  try {
    helperPid = await new Promise((resolve, reject) => {
      let out = "";
      parent.stdout.setEncoding("utf8");
      parent.stdout.on("data", (chunk) => {
        out += chunk;
        const newline = out.indexOf("\n");
        if (newline !== -1) resolve(Number.parseInt(out.slice(0, newline), 10));
      });
      parent.once("error", reject);
      setTimeout(() => reject(new Error("parent did not report the helper pid")), 15_000);
    });

    // The helper is past its own startup and blocked on the release file.
    await waitForFiles([readyPath]);
    assert.equal(processAlive(helperPid), true, "helper should still be waiting before the parent dies");

    parent.kill("SIGKILL");

    const exitedAt = await waitForExit(helperPid, 15_000);
    assert.notEqual(exitedAt, null, `helper ${helperPid} outlived its SIGKILLed parent`);
  } finally {
    if (helperPid && processAlive(helperPid)) {
      try {
        process.kill(helperPid, "SIGKILL");
      } catch {
        // already gone
      }
    }
    if (!parent.killed) parent.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  }
});

// The bounded wait is a second, independent guard: it has to hold even while
// the parent is alive and simply never releases, which parent-death detection
// cannot see. Tested separately so that removing either mechanism fails a test
// rather than being covered by the other.
test("helper gives up waiting while its parent is still alive", { timeout: 30_000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "delivery-deadline-"));
  const storePath = join(dir, "channel-delivered-ids.json");
  const readyPath = join(dir, "ready-deadline");
  const releasePath = join(dir, "release");
  await writeFile(storePath, "{}\n", "utf8");

  const child = spawn(
    process.execPath,
    [helperPath, storePath, readyPath, releasePath, "deadline-msg"],
    { stdio: "ignore", env: { ...process.env, AW_DELIVERY_RELEASE_TIMEOUT_MS: "300" } },
  );
  try {
    const [code, signal] = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
      setTimeout(() => reject(new Error("helper never gave up waiting for the release file")), 20_000);
    });
    // This parent stayed alive throughout, so only the deadline can have ended it.
    assert.equal(signal, null, "helper should exit on its own, not by signal");
    assert.equal(code, 4, "helper should exit with the release-timeout code");
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  }
});
