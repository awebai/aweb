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
import { handleToolCall } from "../src/tools.js";

const execFileAsync = promisify(execFile);
const testDir = dirname(fileURLToPath(import.meta.url));
const channelDir = resolve(testDir, "..");
const repoRoot = resolve(channelDir, "..");
const serverDir = join(repoRoot, "server");

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
  namespace?: string;
  namespace_slug?: string;
  workspace_id?: string;
  did?: string;
  stable_id?: string;
}

interface ToolSigningContext {
  seed: Uint8Array | null;
  did: string;
  stableID: string;
  alias: string;
  projectSlug: string;
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
  let bobDir = "";
  let server: ServerHandle;
  let alice: WorkspaceInfo;
  let bob: WorkspaceInfo;
  let aliceClient: APIClient;
  let bobClient: APIClient;
  let bobSigning: ToolSigningContext;
  let mcpClient: Client | undefined;
  let transport: StdioClientTransport | undefined;
  let notifications: NotificationQueue;
  let channelStderr = "";

  beforeAll(async () => {
    tempRoot = await mkdtemp(join(tmpdir(), "channel-e2e-"));
    homeDir = join(tempRoot, "home");
    bobDir = join(tempRoot, "bob");
    await mkdir(homeDir, { recursive: true });
    await mkdir(bobDir, { recursive: true });

    server = await ensureServer(tempRoot);
    const projectSlug = `channel-e2e-${Date.now()}`;

    alice = await createProject(server.baseURL, {
      project_slug: projectSlug,
      alias: "alice",
    });
    bob = await initWorkspace(server.baseURL, alice.api_key, { alias: "bob" });

    await writeReceiverConfig(homeDir, bobDir, server.baseURL, bob);

    aliceClient = new APIClient(server.baseURL, alice.api_key);
    bobClient = new APIClient(server.baseURL, bob.api_key);
    bobSigning = {
      seed: null,
      did: bob.did || "",
      stableID: bob.stable_id || "",
      alias: bob.alias,
      projectSlug: bob.project_slug,
    };

    notifications = new NotificationQueue();
  }, 300_000);

  afterAll(async () => {
    await transport?.close().catch(() => {});
    await stopServer(server);
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }, 120_000);

  test("mail_inbox reads unread mail from the live server", async () => {
    const body = `mail inbox ${Date.now()}`;
    const mail = await sendMail(aliceClient, "bob", body, "pull mail");

    const result = await handleToolCall("mail_inbox", {}, bobClient, bobSigning);
    const inbox = JSON.parse(result.content[0].text) as Array<Record<string, string>>;

    expect(inbox).toEqual(expect.arrayContaining([
      expect.objectContaining({
        from: "alice",
        subject: "pull mail",
        body,
        message_id: mail.message_id,
      }),
    ]));
  });

  test("chat_pending reads pending conversations from the live server", async () => {
    const body = `chat pending ${Date.now()}`;
    const session = await createChatSession(aliceClient, ["bob"], body, { wait_seconds: 300 });

    const result = await handleToolCall("chat_pending", {}, bobClient, bobSigning);
    const pending = JSON.parse(result.content[0].text) as Array<Record<string, unknown>>;

    expect(pending).toEqual(expect.arrayContaining([
      expect.objectContaining({
        session_id: session.session_id,
        last_message: body,
      }),
    ]));
  });

  test("channel handles MCP tools and SSE against the live server", async () => {
    await startChannelIfNeeded();

    const tools = await mcpClient!.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
      "mail_send",
      "mail_inbox",
      "chat_start",
      "chat_reply",
      "chat_pending",
    ]));

    const mailBody = `mail notification ${Date.now()}`;
    const mail = await sendMail(aliceClient, "bob", mailBody, "e2e mail", "high");
    let mailNotification;
    try {
      mailNotification = await notifications.waitFor(
        (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
      );
    } catch (error) {
      throw new Error(`${String(error)}\nchannel stderr:\n${channelStderr || "(empty)"}`);
    }
    expect(mailNotification.content).toBe(mailBody);
    expect(mailNotification.meta.from).toContain("alice");

    const sentBody = `mail send ${Date.now()}`;
    const sentResult = await mcpClient!.callTool({
      name: "mail_send",
      arguments: { to_alias: "alice", body: sentBody, subject: "tool send" },
    });
    expect(sentResult.content[0]).toMatchObject({ type: "text" });
    const aliceInbox = await fetchInbox(aliceClient);
    expect(aliceInbox).toEqual(expect.arrayContaining([
      expect.objectContaining({ body: sentBody, subject: "tool send" }),
    ]));

    const chatBody = `chat notification ${Date.now()}`;
    const created = await createChatSession(aliceClient, ["bob"], chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.meta.session_id === created.session_id && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toContain("alice");

    const replyBody = `chat reply ${Date.now()}`;
    const replyResult = await mcpClient!.callTool({
      name: "chat_reply",
      arguments: { session_id: created.session_id, body: replyBody },
    });
    expect(replyResult.content[0]).toMatchObject({ type: "text" });
    const aliceHistory = await fetchChatHistory(aliceClient, created.session_id);
    expect(aliceHistory).toEqual(expect.arrayContaining([
      expect.objectContaining({ body: replyBody, from_agent: "bob" }),
    ]));

    const startBody = `chat start ${Date.now()}`;
    const startResult = await mcpClient!.callTool({
      name: "chat_start",
      arguments: { to_alias: "alice", body: startBody },
    });
    expect(startResult.content[0]).toMatchObject({ type: "text" });
    const alicePending = await fetchChatPending(aliceClient);
    expect(alicePending).toEqual(expect.arrayContaining([
      expect.objectContaining({ last_message: startBody }),
    ]));

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

async function createProject(
  baseURL: string,
  payload: { project_slug: string; alias: string },
): Promise<WorkspaceInfo> {
  const response = await fetch(`${baseURL}/api/v1/create-project`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`create-project failed: ${response.status} ${await response.text()}`);
  }
  return response.json() as Promise<WorkspaceInfo>;
}

async function initWorkspace(
  baseURL: string,
  apiKey: string,
  payload: { alias: string },
): Promise<WorkspaceInfo> {
  const response = await fetch(`${baseURL}/v1/workspaces/init`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`workspace init failed: ${response.status} ${await response.text()}`);
  }
  return response.json() as Promise<WorkspaceInfo>;
}

async function writeReceiverConfig(
  homeDir: string,
  workspaceDir: string,
  baseURL: string,
  workspace: WorkspaceInfo,
): Promise<void> {
  const configDir = join(homeDir, ".config", "aw");
  const awDir = join(workspaceDir, ".aw");
  await mkdir(configDir, { recursive: true });
  await mkdir(awDir, { recursive: true });

  const accountName = `acct-e2e__${workspace.project_slug}__${workspace.alias}`;
  const namespaceSlug = workspace.namespace_slug || workspace.namespace || workspace.project_slug;

  await writeFile(join(configDir, "config.yaml"), JSON.stringify({
    servers: {
      e2e: { url: baseURL },
    },
    accounts: {
      [accountName]: {
        server: "e2e",
        api_key: workspace.api_key,
        alias: workspace.alias,
        namespace_slug: namespaceSlug,
        did: workspace.did || "",
        stable_id: workspace.stable_id || "",
        default_project: workspace.project_slug,
      },
    },
  }, null, 2));

  await writeFile(join(awDir, "context"), JSON.stringify({
    default_account: accountName,
    server_accounts: { e2e: accountName },
    client_default_accounts: { aw: accountName },
  }, null, 2));

  await writeFile(join(awDir, "workspace.yaml"), JSON.stringify({
    workspace_id: workspace.workspace_id || workspace.agent_id,
    project_id: workspace.project_id,
    project_slug: workspace.project_slug,
    alias: workspace.alias,
  }, null, 2));
}

async function sendMail(
  client: APIClient,
  toAlias: string,
  body: string,
  subject: string,
  priority: "low" | "normal" | "high" | "urgent" = "normal",
): Promise<{ message_id: string }> {
  return client.post("/v1/messages", { to_alias: toAlias, body, subject, priority });
}

async function fetchInbox(client: APIClient): Promise<Array<Record<string, string>>> {
  const response = await client.get<{ messages: Array<Record<string, string>> }>("/v1/messages/inbox?limit=50");
  return response.messages;
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

async function fetchChatHistory(
  client: APIClient,
  sessionId: string,
): Promise<Array<Record<string, string>>> {
  const response = await client.get<{ messages: Array<Record<string, string>> }>(
    `/v1/chat/sessions/${encodeURIComponent(sessionId)}/messages?limit=50`,
  );
  return response.messages;
}

async function fetchChatPending(
  client: APIClient,
): Promise<Array<Record<string, unknown>>> {
  const response = await client.get<{ pending: Array<Record<string, unknown>> }>("/v1/chat/pending");
  return response.pending;
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
