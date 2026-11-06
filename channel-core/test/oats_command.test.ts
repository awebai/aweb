import { expect, test } from "vitest";
import { runOATS } from "../../cli/go/wake/oats_command.js";

const childProcesses = () => process.getActiveResourcesInfo().filter((type) => type === "ProcessWrap").length;

test.each([0, 300])("OATS timeout kills and reaps the hung subprocess (startup delay %i ms)", async (startupDelay) => {
  const before = childProcesses();
  const script = `setTimeout(() => setInterval(() => {}, 1000), ${startupDelay});`;
  const pending = runOATS(process.execPath, ["-e", script], "", { timeoutMs: 150 });
  // The parent observes the real child even before its JavaScript starts.
  expect(childProcesses()).toBe(before + 1);
  await expect(pending).rejects.toThrow("timed out after 150ms");
  await expect.poll(childProcesses).toBe(before);
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
