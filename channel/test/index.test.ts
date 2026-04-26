import { afterEach, describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { isDirectExecution, resolveRegistryFallbackURL } from "../src/index.js";

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

describe("resolveRegistryFallbackURL", () => {
  const originalRegistryURL = process.env.AWID_REGISTRY_URL;

  afterEach(() => {
    if (originalRegistryURL === undefined) {
      delete process.env.AWID_REGISTRY_URL;
    } else {
      process.env.AWID_REGISTRY_URL = originalRegistryURL;
    }
  });

  test("uses AWID_REGISTRY_URL as a URL override", () => {
    process.env.AWID_REGISTRY_URL = "https://registry.example.test";

    expect(resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toBe("https://registry.example.test");
  });

  test("rejects AWID_REGISTRY_URL=local", () => {
    process.env.AWID_REGISTRY_URL = "local";

    expect(() => resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toThrow("AWID_REGISTRY_URL=local is not supported; set AWID_REGISTRY_URL=https://api.awid.ai");
  });

  test("falls back to identity registry_url when AWID_REGISTRY_URL is unset", () => {
    delete process.env.AWID_REGISTRY_URL;

    expect(resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toBe("https://identity-registry.example.test");
  });

  test("leaves registry fallback unset when no source is configured", () => {
    delete process.env.AWID_REGISTRY_URL;

    expect(resolveRegistryFallbackURL("")).toBeUndefined();
  });
});
