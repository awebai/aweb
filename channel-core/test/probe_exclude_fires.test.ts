import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "vitest";

// vitest.config.ts keeps the recovered probes out of this suite by matching
// '**/zz_probe_*' - by NAME, so the exclude still holds when someone drops the
// .recovered suffix. Two of those probes assert the CURRENT, VULNERABLE behaviour,
// so a collected probe would make this suite assert the defect exists, and fixing
// the defect would turn the suite red.
//
// Until now that exclude was verified by having been exercised once, by hand.
// Nothing would notice a regression: a working exclude and a broken one both leave
// the suite green, because the difference is which files were COLLECTED, not which
// assertions passed. Only the collected list distinguishes them.
//
// The instrument is `vitest list --filesOnly`, which globs without importing, so
// this costs a glob rather than a suite run - channel-core's full suite has starved
// this host before.
//
// These fixtures are SYNTHETIC rather than renames of the real probes. A rename
// that failed to restore - a crash, a killed run - would leave a real probe live in
// the suite, which is the exact state the exclude exists to prevent. A synthetic
// file cannot do that: the worst case is a stray file matching a pattern that
// excludes it.

const TEST_DIR = fileURLToPath(new URL(".", import.meta.url));
const CHANNEL_CORE = join(TEST_DIR, "..");

function collectedFiles(): string[] {
  const result = spawnSync("./node_modules/.bin/vitest", ["list", "--filesOnly"], {
    cwd: CHANNEL_CORE,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`vitest list failed (${result.status}): ${result.stderr}`);
  }
  return result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .sort();
}

function withFixture(name: string, run: () => void): void {
  const path = join(TEST_DIR, name);
  writeFileSync(path, 'import { test, expect } from "vitest";\ntest("fixture", () => expect(1).toBe(1));\n');
  try {
    run();
  } finally {
    rmSync(path, { force: true });
  }
}

test("a probe renamed into a collectable name is still excluded", () => {
  const baseline = collectedFiles();
  expect(baseline.length).toBeGreaterThan(0);

  // The name a recovered probe takes when its .recovered suffix is dropped.
  withFixture("zz_probe_exclude_guard.test.ts", () => {
    const withProbe = collectedFiles();
    // SUCCESS HERE READS LIKE FAILURE: the file is absent from the list.
    expect(withProbe).toEqual(baseline);
  });

  // Positive control, and it catches a NARROWER case than the empty listing - that one
  // is already covered earlier in this test, where an empty baseline fails toBeGreaterThan(0)
  // before this is reached.
  //
  // What only this catches is a listing that does not SEE NEW FILES: stale, cached, or
  // run from the wrong directory. There the baseline is healthy and non-empty, the
  // exclusion assertion above passes FOR THE WRONG REASON - the probe fixture is absent
  // because nothing new is visible, not because the pattern excluded it - and nothing
  // else notices. Writing a file the exclude does NOT match and requiring it to appear
  // is what separates "the pattern worked" from "the instrument saw nothing new".
  withFixture("zz_control_exclude_guard.test.ts", () => {
    const withControl = collectedFiles();
    expect(withControl.length).toBe(baseline.length + 1);
    expect(withControl.some((f) => f.includes("zz_control_exclude_guard"))).toBe(true);
  });
});
