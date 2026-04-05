import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcessWithoutNullStreams, execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { NotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";

import { APIClient } from "../src/api/client.js";
import { RegistryResolver } from "../src/identity/registry.js";

const execFileAsync = promisify(execFile);
const testDir = dirname(fileURLToPath(import.meta.url));
const channelDir = resolve(testDir, "..");
const repoRoot = resolve(channelDir, "..");
const serverDir = join(repoRoot, "server");
const cliDir = join(repoRoot, "cli", "go");
const awBinary = join(cliDir, "aw");

const ChannelNotificationSchema = NotificationSchema.extend({
  method: z.literal("notifications/claude/channel"),
  params: z.object({
    content: z.string(),
    meta: z.record(z.string(), z.string()),
  }),
});

interface WorkspaceInfo {
  api_key: string;
  agent_id: string;
  project_id: string;
  project_slug: string;
  alias: string;
  name?: string;
  address?: string;
  namespace?: string;
  namespace_slug?: string;
  workspace_id?: string;
  did?: string;
  stable_id?: string;
}

interface ServerHandle {
  baseURL: string;
  managed: boolean;
  envFilePath?: string;
  overrideFilePath?: string;
  serverProcess?: ChildProcessWithoutNullStreams;
  serverLogs: string;
}

class NotificationQueue {
  private items: Array<{ content: string; meta: Record<string, string> }> = [];
  private waiters: Array<{
    predicate: (item: { content: string; meta: Record<string, string> }) => boolean;
    resolve: (item: { content: string; meta: Record<string, string> }) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  push(item: { content: string; meta: Record<string, string> }) {
    this.items.push(item);
    const remaining = [];
    for (const waiter of this.waiters) {
      if (waiter.predicate(item)) {
        clearTimeout(waiter.timer);
        waiter.resolve(item);
      } else {
        remaining.push(waiter);
      }
    }
    this.waiters = remaining;
  }

  async waitFor(
    predicate: (item: { content: string; meta: Record<string, string> }) => boolean,
    timeoutMs: number = 20_000,
  ): Promise<{ content: string; meta: Record<string, string> }> {
    const existing = this.items.find(predicate);
    if (existing) return existing;

    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((waiter) => waiter.timer !== timer);
        rejectPromise(new Error("timed out waiting for channel notification"));
      }, timeoutMs);

      this.waiters.push({
        predicate,
        resolve: resolvePromise,
        reject: rejectPromise,
        timer,
      });
    });
  }
}

describe.sequential("channel integration", () => {
  let tempRoot = "";
  let homeDir = "";
  let aliceDir = "";
  let bobDir = "";
  let server: ServerHandle;
  let alice: WorkspaceInfo;
  let bob: WorkspaceInfo;
  let aliceClient: APIClient;
  let mcpClient: Client | undefined;
  let transport: StdioClientTransport | undefined;
  let notifications: NotificationQueue;
  let channelStderr = "";

  beforeAll(async () => {
    tempRoot = await mkdtemp(join(tmpdir(), "channel-e2e-"));
    homeDir = join(tempRoot, "home");
    aliceDir = join(tempRoot, "alice");
    bobDir = join(tempRoot, "bob");
    await mkdir(homeDir, { recursive: true });
    await mkdir(aliceDir, { recursive: true });
    await mkdir(bobDir, { recursive: true });

    server = await ensureServer(tempRoot);
    await ensureAwBinary();
    const projectSlug = `channel-e2e-${Date.now()}`;

    alice = await createProjectViaAW(homeDir, aliceDir, server.baseURL, projectSlug, "alice");
    bob = await initWorkspaceViaAW(homeDir, bobDir, server.baseURL, alice.api_key, "bob");

    aliceClient = new APIClient(server.baseURL, alice.api_key);

    notifications = new NotificationQueue();
  }, 300_000);

  afterAll(async () => {
    await transport?.close().catch(() => {});
    await stopServer(server);
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }, 120_000);

  test("real aw mail verifies through the embedded registry and reaches the channel", async () => {
    const cliBody = `cli verified mail ${Date.now()}`;
    const cliMail = await sendMailViaAW(homeDir, aliceDir, bob.address || "bob", cliBody);
    const inbox = await inboxViaAW(homeDir, bobDir);
    const cliMessage = inbox.messages.find((msg) => msg.message_id === cliMail.message_id);
    expect(cliMessage).toBeDefined();
    expect(cliMessage?.body).toBe(cliBody);
    expect(cliMessage?.verification_status).toBe("verified");
    expect(cliMessage?.from_address).toBe(alice.address);

    const verifiedResolver = new RegistryResolver(fetch, txtNotFoundResolver, () => Date.now(), {
      fallbackRegistryURL: server.baseURL,
    });
    await expect(
      verifiedResolver.verifyStableIdentity(alice.address || "", alice.stable_id || ""),
    ).resolves.toMatchObject({
      outcome: "OK_VERIFIED",
      currentDidKey: alice.did,
    });

    const degradedResolver = new RegistryResolver(async (input, init) => {
      const url = String(input);
      if (url.includes("/v1/did/")) {
        throw new Error("registry unavailable");
      }
      return fetch(input, init);
    }, txtNotFoundResolver, () => Date.now(), {
      fallbackRegistryURL: server.baseURL,
    });
    await expect(
      degradedResolver.verifyStableIdentity(alice.address || "", alice.stable_id || ""),
    ).resolves.toMatchObject({
      outcome: "OK_DEGRADED",
    });

    const hardErrorResolver = new RegistryResolver(async (input, init) => {
      const response = await fetch(input, init);
      const url = String(input);
      if (!url.includes(`/v1/did/${alice.stable_id}/key`)) {
        return response;
      }
      const payload = await response.json() as Record<string, unknown>;
      payload.did_aw = "did:aw:SomeoneElse";
      return jsonResponse(payload);
    }, txtNotFoundResolver, () => Date.now(), {
      fallbackRegistryURL: server.baseURL,
    });
    await expect(
      hardErrorResolver.verifyStableIdentity(alice.address || "", alice.stable_id || ""),
    ).resolves.toMatchObject({
      outcome: "HARD_ERROR",
    });

    await startChannelIfNeeded();

    const channelBody = `channel verified mail ${Date.now()}`;
    const mail = await sendMailViaAW(homeDir, aliceDir, bob.address || "bob", channelBody);
    let mailNotification;
    try {
      mailNotification = await notifications.waitFor(
        (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
      );
    } catch (error) {
      throw new Error(`${String(error)}\nchannel stderr:\n${channelStderr || "(empty)"}`);
    }
    expect(mailNotification.content).toBe(channelBody);
    expect(mailNotification.meta.from).toBe(alice.address);
    expect(mailNotification.meta.verified).toBe("true");

    const chatBody = `chat notification ${Date.now()}`;
    const created = await createChatSession(aliceClient, ["bob"], chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.meta.session_id === created.session_id && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toContain("alice");

    expect(channelStderr).not.toContain("fatal:");
  }, 45_000);

  async function startChannelIfNeeded(): Promise<void> {
    if (mcpClient) return;

    transport = new StdioClientTransport({
      command: process.execPath,
      args: [
        join(channelDir, "node_modules", "tsx", "dist", "cli.mjs"),
        join(channelDir, "src", "index.ts"),
      ],
      cwd: bobDir,
      env: {
        ...stringEnv(process.env),
        HOME: homeDir,
        AWID_REGISTRY_URL: "local",
      },
      stderr: "pipe",
    });
    transport.stderr?.on("data", (chunk) => {
      channelStderr += chunk.toString();
    });

    mcpClient = new Client({ name: "channel-e2e", version: "1.0.0" });
    mcpClient.setNotificationHandler(ChannelNotificationSchema, (notification) => {
      notifications.push(notification.params);
    });

    await mcpClient.connect(transport);
  }
});

async function ensureServer(tempRoot: string): Promise<ServerHandle> {
  const provided = process.env.AWEB_TEST_URL;
  if (provided) {
    await waitForHealthyServer(provided);
    return { baseURL: provided, managed: false, serverLogs: "" };
  }

  if (!(await dockerAvailable())) {
    throw new Error("Docker daemon unavailable; start Docker or set AWEB_TEST_URL");
  }
  if (!(await uvAvailable())) {
    throw new Error("uv is unavailable; install uv or set AWEB_TEST_URL");
  }

  const [appPort, pgPort, redisPort] = await Promise.all([
    getFreePort(),
    getFreePort(),
    getFreePort(),
  ]);

  const envFilePath = join(tempRoot, ".env.integration");
  const overrideFilePath = join(tempRoot, "docker-compose.override.yml");
  const postgresUser = "aweb";
  const postgresPassword = "aweb-e2e-test";
  const postgresDb = "aweb";

  await writeFile(envFilePath, [
    `POSTGRES_USER=${postgresUser}`,
    `POSTGRES_PASSWORD=${postgresPassword}`,
    `POSTGRES_DB=${postgresDb}`,
    `POSTGRES_PORT=${pgPort}`,
    `REDIS_PORT=${redisPort}`,
  ].join("\n"));

  await writeFile(overrideFilePath, [
    "services:",
    "  redis:",
    "    ports:",
    '      - "${REDIS_PORT}:6379"',
    "  postgres:",
    "    ports:",
    '      - "${POSTGRES_PORT}:5432"',
  ].join("\n"));

  await runCommand("docker", [
    "compose",
    "-f", join(serverDir, "docker-compose.yml"),
    "-f", overrideFilePath,
    "--env-file", envFilePath,
    "down",
    "-v",
  ], { cwd: serverDir, allowFailure: true });

  await runCommand("docker", [
    "compose",
    "-f", join(serverDir, "docker-compose.yml"),
    "-f", overrideFilePath,
    "--env-file", envFilePath,
    "up",
    "-d",
    "postgres",
    "redis",
  ], { cwd: serverDir, timeoutMs: 120_000 });

  const serverLogs: string[] = [];
  const serverProcess = spawn("uv", ["run", "aweb", "serve"], {
    cwd: serverDir,
    env: {
      ...stringEnv(process.env),
      AWEB_DATABASE_URL: `postgresql://${postgresUser}:${postgresPassword}@127.0.0.1:${pgPort}/${postgresDb}`,
      AWEB_REDIS_URL: `redis://127.0.0.1:${redisPort}/0`,
      AWEB_HOST: "127.0.0.1",
      AWEB_PORT: String(appPort),
      AWEB_CUSTODY_KEY: randomHex(64),
      AWEB_MANAGED_DOMAIN: "aweb.local",
      AWID_REGISTRY_URL: "local",
      PYTHONUNBUFFERED: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  serverProcess.stdout.on("data", (chunk) => serverLogs.push(chunk.toString()));
  serverProcess.stderr.on("data", (chunk) => serverLogs.push(chunk.toString()));

  const baseURL = `http://127.0.0.1:${appPort}`;
  try {
    await waitForHealthyServer(baseURL);
  } catch (error) {
    await stopServer({
      baseURL,
      managed: true,
      envFilePath,
      overrideFilePath,
      serverProcess,
      serverLogs: serverLogs.join(""),
    });
    throw new Error(`server failed to become healthy: ${serverLogs.join("") || String(error)}`);
  }

  return {
    baseURL,
    managed: true,
    envFilePath,
    overrideFilePath,
    serverProcess,
    serverLogs: serverLogs.join(""),
  };
}

async function stopServer(server: ServerHandle | undefined): Promise<void> {
  if (!server) return;

  if (server.serverProcess && !server.serverProcess.killed) {
    server.serverProcess.kill("SIGTERM");
    await waitForProcessExit(server.serverProcess, 5_000).catch(() => {
      server.serverProcess?.kill("SIGKILL");
    });
  }

  if (server.managed && server.envFilePath && server.overrideFilePath) {
    await runCommand("docker", [
      "compose",
      "-f", join(serverDir, "docker-compose.yml"),
      "-f", server.overrideFilePath,
      "--env-file", server.envFilePath,
      "down",
      "-v",
    ], { cwd: serverDir, allowFailure: true });
    await rm(server.envFilePath, { force: true }).catch(() => {});
    await rm(server.overrideFilePath, { force: true }).catch(() => {});
  }
}

async function createChatSession(
  client: APIClient,
  toAliases: string[],
  message: string,
  extra: Record<string, unknown> = {},
): Promise<{ session_id: string; message_id: string }> {
  return client.post("/v1/chat/sessions", {
    to_aliases: toAliases,
    message,
    ...extra,
  });
}

async function waitForHealthyServer(baseURL: string): Promise<void> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseURL}/health`);
      if (response.ok) {
        const health = await response.json() as { status?: string };
        if (health.status === "ok") return;
      }
    } catch {}
    await delay(1_000);
  }
  throw new Error(`server at ${baseURL} did not become healthy`);
}

async function ensureAwBinary(): Promise<void> {
  const result = await runCommand("make", ["build"], {
    cwd: cliDir,
    timeoutMs: 120_000,
  });
  if (!result.ok) {
    throw new Error(`aw build failed:\n${result.stderr || result.stdout}`);
  }
}

async function createProjectViaAW(
  homeDir: string,
  workspaceDir: string,
  baseURL: string,
  projectSlug: string,
  name: string,
): Promise<WorkspaceInfo> {
  return runAwJSON<WorkspaceInfo>(homeDir, workspaceDir, [
    "--json",
    "project",
    "create",
    "--server-url", baseURL,
    "--project", projectSlug,
    "--name", name,
    "--permanent",
  ]);
}

async function initWorkspaceViaAW(
  homeDir: string,
  workspaceDir: string,
  baseURL: string,
  apiKey: string,
  name: string,
): Promise<WorkspaceInfo> {
  return runAwJSON<WorkspaceInfo>(homeDir, workspaceDir, [
    "--json",
    "init",
    "--server-url", baseURL,
    "--name", name,
    "--permanent",
  ], { AWEB_API_KEY: apiKey });
}

async function sendMailViaAW(
  homeDir: string,
  workspaceDir: string,
  to: string,
  body: string,
): Promise<{ message_id: string }> {
  return runAwJSON<{ message_id: string }>(homeDir, workspaceDir, [
    "--json",
    "mail",
    "send",
    "--to", to,
    "--body", body,
  ]);
}

async function inboxViaAW(
  homeDir: string,
  workspaceDir: string,
): Promise<{ messages: Array<{ message_id: string; body: string; from_address?: string; verification_status?: string }> }> {
  return runAwJSON(homeDir, workspaceDir, ["--json", "mail", "inbox"]);
}

async function runAwJSON<T>(
  homeDir: string,
  workspaceDir: string,
  args: string[],
  extraEnv: Record<string, string> = {},
): Promise<T> {
  const result = await execFileAsync(awBinary, args, {
    cwd: workspaceDir,
    encoding: "utf8",
    env: {
      ...stringEnv(process.env),
      ...extraEnv,
      HOME: homeDir,
      AW_CONFIG_PATH: join(homeDir, ".config", "aw", "config.yaml"),
      AWID_REGISTRY_URL: "local",
    },
    maxBuffer: 10 * 1024 * 1024,
  });
  return JSON.parse(result.stdout) as T;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

async function txtNotFoundResolver(): Promise<string[][]> {
  throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
}

async function runCommand(
  command: string,
  args: string[],
  options: { cwd: string; allowFailure?: boolean; timeoutMs?: number },
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(command, args, {
      cwd: options.cwd,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
      timeout: options.timeoutMs ?? 30_000,
    });
    return { ok: true, stdout: result.stdout.trim(), stderr: result.stderr.trim() };
  } catch (error) {
    if (options.allowFailure) {
      const failed = error as Error & { stdout?: string; stderr?: string };
      return {
        ok: false,
        stdout: String(failed.stdout || "").trim(),
        stderr: String(failed.stderr || "").trim(),
      };
    }
    throw error;
  }
}

async function dockerAvailable(): Promise<boolean> {
  const result = await runCommand("docker", ["info"], {
    cwd: repoRoot,
    allowFailure: true,
    timeoutMs: 5_000,
  });
  return result.ok && !result.stderr.includes("Cannot connect to the Docker daemon");
}

async function uvAvailable(): Promise<boolean> {
  const result = await runCommand("uv", ["--version"], {
    cwd: serverDir,
    allowFailure: true,
    timeoutMs: 5_000,
  });
  return result.ok && result.stdout.startsWith("uv ");
}

async function waitForProcessExit(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => rejectPromise(new Error("process did not exit")), timeoutMs);
    child.once("exit", () => {
      clearTimeout(timer);
      resolvePromise();
    });
  });
}

async function getFreePort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        rejectPort(new Error("failed to allocate port"));
        return;
      }
      const port = address.port;
      server.close((error) => {
        if (error) rejectPort(error);
        else resolvePort(port);
      });
    });
    server.on("error", rejectPort);
  });
}

function stringEnv(source: NodeJS.ProcessEnv): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === "string") env[key] = value;
  }
  return env;
}

function randomHex(length: number): string {
  const chars = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}
