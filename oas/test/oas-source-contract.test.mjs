import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";

const REPO_ROOT = resolve(new URL("../..", import.meta.url).pathname);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function contractlessOasRoot() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "aweb-contractless-oas-")));
  temporaryDirectories.push(root);
  const core = join(root, "lib", "core.mjs");
  const schema = join(root, "docs", "capability-manifest.schema.json");
  mkdirSync(dirname(core), { recursive: true });
  mkdirSync(dirname(schema), { recursive: true });
  writeFileSync(core, "export function spawnInstance() {}\n");
  writeFileSync(schema, JSON.stringify({ type: "object", properties: {} }) + "\n");
  return root;
}

test(
  "OAS suite fails fast with a readable diagnostic when OAS_TEST_ROOT lacks the launch-environment contract",
  { skip: process.env.AWEB_OAS_CONTRACT_NEGATIVE_NESTED === "1" },
  () => {
    const root = contractlessOasRoot();
    const result = spawnSync(
      "make",
      ["--no-print-directory", "test-oas", `OAS_TEST_ROOT=${root}`],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
        env: { ...process.env, AWEB_OAS_CONTRACT_NEGATIVE_NESTED: "1" },
      },
    );

    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /OAS_TEST_ROOT .* lacks the required launch-environment contract/);
    assert.match(result.stderr, /upstream PR 48/);
    assert.doesNotMatch(result.stderr, /AssertionError|ERR_MODULE_NOT_FOUND/);
  },
);

test("test-oas checks the launch-environment contract before starting assertions", () => {
  const makefile = readFileSync(join(REPO_ROOT, "Makefile"), "utf8");
  assert.match(makefile, /^test-oas:\s+check-oas-launch-environment-contract$/m);
});
