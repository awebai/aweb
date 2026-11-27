// The host owner's opt-in: <identity root>/activity.yaml (docs/agent-activity.md,
// "Host-owner opt-in"). Anything but exactly `activity: status` is off.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { readActivitySetting } from "../src/activity/setting.js";

let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "activity-setting-")); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

function write(content: string): void {
  writeFileSync(join(root, "activity.yaml"), content);
}

describe("readActivitySetting", () => {
  test("a missing file is off", () => {
    expect(readActivitySetting(root)).toBe("off");
  });

  test("activity: status turns publishing on", () => {
    write("activity: status\n");
    expect(readActivitySetting(root)).toBe("status");
  });

  test.each([
    ["off", "activity: off\n"],
    ["an unknown level", "activity: full\n"],
    ["another case", "activity: STATUS\n"],
    ["a boolean", "activity: true\n"],
    ["no activity key", "other: status\n"],
    ["a list", "- activity: status\n"],
    ["invalid YAML", "activity: [status\n"],
    ["an empty file", ""],
  ])("%s is off", (_name, content) => {
    write(content);
    expect(readActivitySetting(root)).toBe("off");
  });

  test("each read sees the current file", () => {
    write("activity: status\n");
    expect(readActivitySetting(root)).toBe("status");
    write("activity: off\n");
    expect(readActivitySetting(root)).toBe("off");
  });
});
