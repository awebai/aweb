// The Claude Code plugin's activity from a real identity home: hook events
// forwarded to the plugin's socket become signed activity published to the
// server, and stopping closes the socket and the open turn. A local HTTP
// server records what the plugin publishes.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { resolveConfig } from "@awebai/channel-core";
import { writeTestPrincipal } from "../../channel-core/test/helpers/config_fixture.js";
import { startClaudeActivity } from "../src/activity.js";
import { activitySocketPath, ensureOwnerOnlyDir, forwardHookEvent } from "../src/activity_socket.js";

let root: string;
let server: Server;
let published: { phase: string; tool?: string; summary?: string; from_did: string }[];

beforeEach(async () => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "cact-")));
  published = [];
  server = createServer((request, response) => {
    let body = "";
    request.on("data", chunk => (body += chunk));
    request.on("end", () => {
      if (request.url === "/v1/agents/me/activity") {
        const signed = JSON.parse(body).signed_payload as string;
        published.push(JSON.parse(Buffer.from(signed, "base64url").toString("utf8")));
      }
      response.writeHead(202);
      response.end();
    });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
});
afterEach(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
  rmSync(root, { recursive: true, force: true });
});

async function plugin(optIn = true) {
  const home = join(root, ".aw");
  const principal = await writeTestPrincipal(home, { alias: "agent", seedByte: 9, teamID: "default:acme.aweb.ai" });
  const { port } = server.address() as AddressInfo;
  const workspace = join(home, "workspace.yaml");
  writeFileSync(workspace, readFileSync(workspace, "utf8").replace("https://app.aweb.ai", `http://127.0.0.1:${port}`));
  if (optIn) writeFileSync(join(home, "activity.yaml"), "activity: status\n");
  const config = await resolveConfig(root, { identityHome: home });
  const dir = join(root, "s");
  ensureOwnerOnlyDir(dir);
  const logs: string[] = [];
  const activity = await startClaudeActivity(config, root, { claudePid: process.pid, dir, log: line => logs.push(line) });
  return { activity, dir, logs, principal };
}

async function hook(dir: string, event: object): Promise<void> {
  await forwardHookEvent(event as never, { dir, candidates: [process.pid] });
}

async function settled(ms = 700): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms));
}

describe("startClaudeActivity", () => {
  test("hook events become signed activity, and stop closes the turn and the socket", async () => {
    const { activity, dir, principal } = await plugin();
    expect(activity).toBeDefined();

    await hook(dir, { hook_event_name: "UserPromptSubmit" });
    await settled();
    await hook(dir, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pytest -q" } });
    await settled();
    await activity!.stop();

    expect(published.map(event => event.phase)).toEqual(["turn_started", "tool", "turn_ended"]);
    expect(published[1]).toMatchObject({ tool: "Bash", summary: "Running pytest" });
    expect(new Set(published.map(event => event.from_did))).toEqual(new Set([principal.did]));
    expect(existsSync(activitySocketPath(process.pid, dir))).toBe(false);
  });

  test("stopping an idle session publishes nothing", async () => {
    const { activity } = await plugin();
    await activity!.stop();
    expect(published).toEqual([]);
  });

  test("an unsafe socket directory leaves activity off, with one log line", async () => {
    const home = join(root, ".aw");
    await writeTestPrincipal(home, { alias: "agent", seedByte: 9, teamID: "default:acme.aweb.ai" });
    const config = await resolveConfig(root, { identityHome: home });
    const dir = join(root, "open");
    mkdirSync(dir, { mode: 0o755 });
    chmodSync(dir, 0o755);
    const logs: string[] = [];

    const activity = await startClaudeActivity(config, root, { claudePid: process.pid, dir, log: line => logs.push(line) });

    expect(activity).toBeUndefined();
    expect(logs).toHaveLength(1);
    expect(logs[0]).toMatch(/activity is off/);
  });
});
