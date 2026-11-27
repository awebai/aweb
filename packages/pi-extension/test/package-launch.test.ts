import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const run = promisify(execFile);

test("freshly built Pi ESM bundle loads in an ESM process", async () => {
  const result = await run(process.execPath, [fileURLToPath(new URL("../dist/index.js", import.meta.url))]);

  assert.equal(result.stderr, "");
});
