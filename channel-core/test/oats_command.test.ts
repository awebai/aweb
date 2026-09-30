import { expect, test } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runOATS } from "../../cli/go/wake/oats_command.js";

test("OATS timeout kills and reaps the hung subprocess", async () => {
  const root = await mkdtemp(join(tmpdir(), "aweb-oats-timeout-"));
  const pidPath = join(root, "pid");
  try {
    const script = `require('fs').writeFileSync(${JSON.stringify(pidPath)}, String(process.pid)); setInterval(() => {}, 1000);`;
    await expect(runOATS(process.execPath, ["-e", script], "", { timeoutMs: 150 })).rejects.toThrow("timed out after 150ms");
    const pid = Number(await readFile(pidPath, "utf8"));
    expect(() => process.kill(pid, 0)).toThrow();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("OATS abort waits for the command to exit and removes its listener", async () => {
  const controller = new AbortController();
  const pending = runOATS(process.execPath, ["-e", "setInterval(() => {},1000)"], "", { signal: controller.signal });
  controller.abort();
  await expect(pending).rejects.toThrow("oats command aborted");
});

test("OATS normal completion returns its envelope and clears timeout", async () => {
  const result = await runOATS(process.execPath, ["-e", `console.log(JSON.stringify({ok:true,result:{present:true,state:'idle'}}))`], "", { timeoutMs: 1000 });
  expect(result.result?.state).toBe("idle");
});
