import { afterEach, describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { isDirectExecution } from "../src/index.js";

describe("isDirectExecution", () => {
  const originalArgv1 = process.argv[1];
  let tempDir: string | null = null;

  afterEach(() => {
    process.argv[1] = originalArgv1;
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
      tempDir = null;
    }
  });

  test("treats the npm bin symlink as direct execution", () => {
    tempDir = mkdtempSync(join(tmpdir(), "channel-bin-"));

    const target = join(tempDir, "node_modules", "@awebai", "channel", "dist", "index.js");
    mkdirSync(join(tempDir, "node_modules", ".bin"), { recursive: true });
    mkdirSync(join(tempDir, "node_modules", "@awebai", "channel", "dist"), { recursive: true });
    writeFileSync(target, "#!/usr/bin/env node\n");

    const binPath = join(tempDir, "node_modules", ".bin", "channel");
    symlinkSync(target, binPath);

    process.argv[1] = binPath;

    expect(isDirectExecution(pathToFileURL(target).href)).toBe(true);
  });
});
