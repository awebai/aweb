// The host owner's activity opt-in (docs/agent-activity.md, "Host-owner opt-in"):
// one file in the identity root the emitter signs with. Publishing is on only
// for exactly `activity: status`; a missing, unreadable or different file is off.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

export type ActivitySetting = "off" | "status";

export const ACTIVITY_SETTING_FILE = "activity.yaml";

/** Read on every call, so a change takes effect at the next turn. */
export function readActivitySetting(identityRoot: string): ActivitySetting {
  let parsed: unknown;
  try {
    parsed = yaml.load(readFileSync(join(identityRoot, ACTIVITY_SETTING_FILE), "utf8"));
  } catch {
    return "off";
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return "off";
  return (parsed as Record<string, unknown>).activity === "status" ? "status" : "off";
}
