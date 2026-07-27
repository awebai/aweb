#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";

const selectedRoot = process.env.OAS_TEST_ROOT;
const expectedContract = [
  ["lib/core.mjs", "class HookEnvironmentContractError extends Error"],
  ["lib/core.mjs", "is not declared in its trusted manifest environment"],
  ["lib/core.mjs", "hook env is supported only for spawn"],
  ["lib/core.mjs", "const hookEnv = Object.keys(hookRes.env).sort()"],
  ["bin/oas.mjs", "Requested launch environment:"],
];

function fail(root, missing) {
  const location = root || "<unset>";
  process.stderr.write(
    `ERROR: OAS_TEST_ROOT ${location} lacks the required launch-environment contract.\n`
    + "The aweb OAS seam tests currently depend on unreleased upstream PR 48; published OAS 0.18.6 does not contain this contract.\n"
    + "Point OAS_TEST_ROOT at the reviewed launch-environment-contract checkout before running test-oas.\n"
    + `Missing contract evidence: ${missing.join(", ")}\n`
    + "This diagnostic makes the source coupling visible; it does not make the suite independent of that checkout.\n",
  );
  process.exitCode = 1;
}

if (!selectedRoot) {
  fail(selectedRoot, ["OAS_TEST_ROOT"]);
} else {
  let root;
  try {
    root = realpathSync(resolve(selectedRoot));
  } catch {
    fail(selectedRoot, ["selected root"]);
  }

  if (root) {
    const missing = [];
    for (const [relativePath, marker] of expectedContract) {
      const path = join(root, relativePath);
      let content;
      try {
        content = readFileSync(path, "utf8");
      } catch {
        content = "";
      }
      if (!content.includes(marker)) missing.push(`${relativePath}:${marker}`);
    }

    const schemaPath = join(root, "docs", "capability-manifest.schema.json");
    try {
      const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
      const environment = schema?.properties?.environment;
      if (
        environment?.type !== "array"
        || environment?.items?.type !== "string"
        || environment?.uniqueItems !== true
      ) {
        missing.push("docs/capability-manifest.schema.json:properties.environment");
      }
    } catch {
      missing.push("docs/capability-manifest.schema.json:properties.environment");
    }

    if (missing.length) fail(root, missing);
  }
}
