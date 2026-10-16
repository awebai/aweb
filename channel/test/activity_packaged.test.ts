// The packaged plugin's activity, launched as Claude Code launches it (from
// .mcp.json, as this process's child): hook events forwarded to its socket are
// published, and when Claude Code closes the session the open turn is ended.
// External delivery keeps the plugin off the event stream; activity runs in
// either delivery mode.
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { writeTestPrincipal } from "../../channel-core/test/helpers/config_fixture.js";
import { activitySocketDir, activitySocketPath, forwardHookEvent } from "../src/activity_socket.js";
import { launchPackagedMCPChild } from "./helpers/packaged_mcp.js";

const CHANNEL_ROOT = fileURLToPath(new URL("..", import.meta.url));
const DIR = activitySocketDir(process.getuid!());
const SOCKET = activitySocketPath(process.pid, DIR);

let root: string;
let server: Server;
let published: string[];

beforeEach(async () => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "cpkg-")));
  published = [];
  server = createServer((request, response) => {
    let body = "";
    request.on("data", chunk => (body += chunk));
    request.on("end", () => {
      if (request.url === "/v1/agents/me/activity") {
        const signed = JSON.parse(body).signed_payload as string;
        published.push(JSON.parse(Buffer.from(signed, "base64url").toString("utf8")).phase);
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

async function until(condition: () => boolean, ms = 5000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

describe("packaged plugin activity", () => {
  test("publishes the session's hook events and ends the turn when the session closes", async () => {
    const home = join(root, ".aw");
    await writeTestPrincipal(home, { alias: "agent", seedByte: 11, teamID: "default:acme.aweb.ai" });
    const { port } = server.address() as AddressInfo;
    const workspace = join(home, "workspace.yaml");
    writeFileSync(workspace, readFileSync(workspace, "utf8").replace("https://app.aweb.ai", `http://127.0.0.1:${port}`));
    writeFileSync(join(home, "activity.yaml"), "activity: status\n");

    const plugin = await launchPackagedMCPChild(CHANNEL_ROOT, root, { AWEB_IDENTITY_HOME: home, AWEB_DELIVERY: "session" });
    try {
      await until(() => existsSync(SOCKET));
      await forwardHookEvent({ hook_event_name: "UserPromptSubmit" }, { dir: DIR, candidates: [process.pid] });
      await new Promise(resolve => setTimeout(resolve, 700));
      await forwardHookEvent(
        { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pytest" } },
        { dir: DIR, candidates: [process.pid] },
      );
      await until(() => published.length === 2);

      const exited = new Promise(resolve => plugin.child.once("exit", resolve));
      plugin.child.stdin.end();
      await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 5000))]);

      expect(published).toEqual(["turn_started", "tool", "turn_ended"]);
      expect(existsSync(SOCKET)).toBe(false);
    } finally {
      plugin.child.kill("SIGKILL");
    }
  });

  test("a signalled plugin ends the open turn and removes its socket", async () => {
    const home = join(root, ".aw");
    await writeTestPrincipal(home, { alias: "agent", seedByte: 12, teamID: "default:acme.aweb.ai" });
    const { port } = server.address() as AddressInfo;
    const workspace = join(home, "workspace.yaml");
    writeFileSync(workspace, readFileSync(workspace, "utf8").replace("https://app.aweb.ai", `http://127.0.0.1:${port}`));
    writeFileSync(join(home, "activity.yaml"), "activity: status\n");

    const plugin = await launchPackagedMCPChild(CHANNEL_ROOT, root, { AWEB_IDENTITY_HOME: home, AWEB_DELIVERY: "session" });
    try {
      await until(() => existsSync(SOCKET));
      await forwardHookEvent({ hook_event_name: "UserPromptSubmit" }, { dir: DIR, candidates: [process.pid] });
      await until(() => published.length === 1);

      const exited = new Promise<NodeJS.Signals | null>(resolve => plugin.child.once("exit", (_code, signal) => resolve(signal)));
      plugin.child.kill("SIGTERM");
      const signal = await Promise.race([exited, new Promise<null>(resolve => setTimeout(() => resolve(null), 5000))]);

      expect(signal).toBe("SIGTERM");
      expect(published).toEqual(["turn_started", "turn_ended"]);
      expect(existsSync(SOCKET)).toBe(false);
    } finally {
      plugin.child.kill("SIGKILL");
    }
  });
});
