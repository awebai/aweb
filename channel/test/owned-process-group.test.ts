import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  processGroupExists,
  processGroupIDForPID,
  stopOwnedProcessTree,
} from "./helpers/owned_process_group.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(__dirname, "../../scripts/e2e/fixtures/stubborn-process-tree.mjs");
let cleanup: (() => void) | undefined;

afterEach(() => cleanup?.());

describe.skipIf(process.platform === "win32")("owned process-group cleanup", () => {
  it("kills and proves termination of a descendant that survives its parent SIGTERM", async () => {
    const root = mkdtempSync(path.join(tmpdir(), "aweb-owned-process-group-"));
    const marker = path.join(root, "pids.json");
    const parent = spawn(process.execPath, [fixture, marker], {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    cleanup = () => {
      if (parent.pid && processGroupExists(parent.pid)) {
        try { process.kill(-parent.pid, "SIGKILL"); } catch {}
      }
      rmSync(root, { recursive: true, force: true });
    };

    await waitUntil(() => existsSync(marker), 5_000);
    const pids = JSON.parse(readFileSync(marker, "utf8")) as {
      parent_pid: number;
      descendant_pid: number;
    };
    expect(pids.parent_pid).toBe(parent.pid);

    const processGroupID = processGroupIDForPID(parent.pid!);
    expect(processGroupID).toBe(parent.pid);
    const proof = await stopOwnedProcessTree(parent, processGroupID!, 500);

    expect(proof.observed_pids).toContain(pids.parent_pid);
    expect(proof.observed_pids).toContain(pids.descendant_pid);
    expect(proof.sigkill_required).toBe(true);
    expect(proof.termination_proven).toBe(true);
    expect(processGroupExists(pids.parent_pid)).toBe(false);
    expect(pidExists(pids.descendant_pid)).toBe(false);
  });
});

function pidExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`condition not met within ${timeoutMs}ms`);
}
