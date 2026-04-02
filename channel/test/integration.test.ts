import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { NotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";

import { APIClient } from "../src/api/client.js";
import { handleToolCall } from "../src/tools.js";
import { resolveConfig } from "../src/config.js";
import { loadSigningKey } from "../src/identity/keys.js";

const execFileAsync = promisify(execFile);
const testDir = dirname(fileURLToPath(import.meta.url));
const channelDir = resolve(testDir, "..");
const repoRoot = resolve(channelDir, "..");
const cliDir = join(repoRoot, "cli", "go");
const serverDir = join(repoRoot, "server");
const runChannelE2E = process.env.AWEB_CHANNEL_E2E === "1" || !!process.env.AWEB_CHANNEL_SERVER_URL;
const describeIf = runChannelE2E ? describe.sequential : describe.skip;

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
  alias: string;
  project_slug?: string;
  namespace?: string;
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
  envFilePath?: string;
  managed: boolean;
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

  waitFor(
    predicate: (item: { content: string; meta: Record<string, string> }) => boolean,
    timeoutMs: number = 20_000,
  ): Promise<{ content: string; meta: Record<string, string> }> {
    const existing = this.items.find(predicate);
    if (existing) return Promise.resolve(existing);

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

let homeDir = "";

describeIf("channel integration", () => {
  let tempRoot = "";
  let aliceDir = "";
  let bobDir = "";
  let server: ServerHandle | undefined;
  let alice: WorkspaceInfo;
  let bob: WorkspaceInfo;
  let aliceClient: APIClient;
  let bobClient: APIClient;
  let bobSigning: ToolSigningContext;
  let mcpClient: Client;
  let transport: StdioClientTransport;
  let notifications: NotificationQueue;
  let channelStderr = "";
  let aliceWaitAbort: AbortController | undefined;
  let aliceWaitResponse: Response | undefined;

  beforeAll(async () => {
    tempRoot = await mkdtemp(join(tmpdir(), "channel-e2e-"));
    homeDir = join(tempRoot, "home");
    aliceDir = join(tempRoot, "alice");
    bobDir = join(tempRoot, "bob");
    await mkdir(homeDir, { recursive: true });
    await mkdir(aliceDir, { recursive: true });
    await mkdir(bobDir, { recursive: true });

    server = await ensureServer();
    await buildAwCli();

    alice = await runAwJson<WorkspaceInfo>(
      aliceDir,
      ["project", "create", "--server-url", server.baseURL, "--project", `channel-e2e-${Date.now()}`, "--alias", "alice", "--json"],
    );
    bob = await runAwJson<WorkspaceInfo>(
      bobDir,
      ["init", "--server-url", server.baseURL, "--alias", "bob", "--json"],
      { AWEB_API_KEY: alice.api_key },
    );

    aliceClient = new APIClient(server.baseURL, alice.api_key);

    const configPath = join(homeDir, ".config", "aw", "config.yaml");
    process.env.AW_CONFIG_PATH = configPath;
    const bobConfig = await resolveConfig(bobDir);
    bobClient = new APIClient(bobConfig.baseURL, bobConfig.apiKey);
    bobSigning = {
      seed: bobConfig.signingKeyPath ? await loadSigningKey(bobConfig.signingKeyPath) : null,
      did: bobConfig.did,
      stableID: bobConfig.stableID,
      alias: bobConfig.alias,
      projectSlug: bobConfig.projectSlug,
    };

    notifications = new NotificationQueue();
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
        AW_CONFIG_PATH: configPath,
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
  }, 300_000);

  afterAll(async () => {
    delete process.env.AW_CONFIG_PATH;
    aliceWaitAbort?.abort();
    await aliceWaitResponse?.body?.cancel().catch(() => {});
    await transport?.close().catch(() => {});

    if (server?.managed && server.envFilePath) {
      await runCommand(
        "docker",
        ["compose", "--env-file", server.envFilePath, "down", "-v"],
        { cwd: serverDir, allowFailure: true },
      );
    }

    if (server?.envFilePath) {
      await rm(server.envFilePath, { force: true }).catch(() => {});
    }
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }, 120_000);

  test("lists tools and delivers mail notifications", async () => {
    const tools = await mcpClient.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
      "mail_send",
      "mail_ack",
      "mail_inbox",
      "chat_start",
      "chat_reply",
      "chat_mark_read",
      "chat_pending",
    ]));

    const mailBody = `mail notification ${Date.now()}`;
    const mail = await sendMail(aliceClient, "bob", mailBody, "e2e mail", "high");
    const notification = await notifications.waitFor(
      (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
    );

    expect(notification.content).toBe(mailBody);
    expect(notification.meta.from).toContain("alice");
    expect(channelStderr).not.toContain("fatal:");
  }, 30_000);

  test("handles tools against the live server", async () => {
    const pullMailBody = `mail inbox ${Date.now()}`;
    const unreadMail = await sendMail(aliceClient, "bob", pullMailBody, "pull mail");
    const inboxResult = await handleToolCall("mail_inbox", {}, bobClient, bobSigning);
    const inbox = JSON.parse(inboxResult.content[0].text) as Array<Record<string, string>>;

    expect(inbox).toEqual(expect.arrayContaining([
      expect.objectContaining({
        from: "alice",
        subject: "pull mail",
        body: pullMailBody,
        message_id: unreadMail.message_id,
      }),
    ]));

    const ackResult = await mcpClient.callTool({
      name: "mail_ack",
      arguments: { message_id: unreadMail.message_id },
    });
    expect(ackResult.content[0]).toMatchObject({ type: "text", text: "acknowledged" });
    expect(await fetchInbox(bobClient, unreadMail.message_id, true)).toBeUndefined();

    const sentBody = `mail send ${Date.now()}`;
    const sentResult = await mcpClient.callTool({
      name: "mail_send",
      arguments: { to_alias: "alice", body: sentBody, subject: "tool send", priority: "urgent" },
    });
    expect(sentResult.content[0]).toMatchObject({ type: "text" });
    const aliceInbox = await fetchInboxForClient(aliceClient);
    expect(aliceInbox).toEqual(expect.arrayContaining([
      expect.objectContaining({ body: sentBody, subject: "tool send" }),
    ]));

    const chatBody = `chat pending ${Date.now()}`;
    const created = await createChatSession(aliceClient, ["bob"], chatBody, {
      wait_seconds: 300,
    });
    aliceWaitAbort = new AbortController();
    aliceWaitResponse = await openChatStream(
      server.baseURL,
      alice.api_key,
      created.session_id,
      aliceWaitAbort.signal,
    );

    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.meta.session_id === created.session_id && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toContain("alice");

    const pendingResult = await handleToolCall("chat_pending", {}, bobClient, bobSigning);
    const pending = JSON.parse(pendingResult.content[0].text) as Array<Record<string, unknown>>;
    expect(pending).toEqual(expect.arrayContaining([
      expect.objectContaining({
        session_id: created.session_id,
        last_message: chatBody,
        sender_waiting: true,
      }),
    ]));

    const replyBody = `chat reply ${Date.now()}`;
    const replyResult = await mcpClient.callTool({
      name: "chat_reply",
      arguments: { session_id: created.session_id, body: replyBody },
    });
    expect(replyResult.content[0]).toMatchObject({ type: "text" });
    const aliceHistoryAfterReply = await fetchChatHistory(aliceClient, created.session_id);
    expect(aliceHistoryAfterReply).toEqual(expect.arrayContaining([
      expect.objectContaining({ body: replyBody, from_agent: "bob" }),
    ]));

    const markReadResult = await mcpClient.callTool({
      name: "chat_mark_read",
      arguments: {
        session_id: created.session_id,
        up_to_message_id: chatNotification.meta.message_id,
      },
    });
    expect(markReadResult.content[0]).toMatchObject({ type: "text", text: "marked read" });

    aliceWaitAbort.abort();
    await aliceWaitResponse.body?.cancel().catch(() => {});
    aliceWaitAbort = undefined;
    aliceWaitResponse = undefined;

    const startBody = `chat start ${Date.now()}`;
    const startResult = await mcpClient.callTool({
      name: "chat_start",
      arguments: { to_alias: "alice", body: startBody },
    });
    expect(startResult.content[0]).toMatchObject({ type: "text" });
    const alicePending = await fetchChatPending(aliceClient);
    expect(alicePending).toEqual(expect.arrayContaining([
      expect.objectContaining({ last_message: startBody }),
    ]));
  }, 45_000);
});

async function ensureServer(): Promise<ServerHandle> {
  const provided = process.env.AWEB_CHANNEL_SERVER_URL;
  if (provided) {
    await waitForHealthyServer(provided);
    return { baseURL: provided, managed: false };
  }

  if (!(await dockerAvailable())) {
    throw new Error("Docker daemon unavailable; start Docker or set AWEB_CHANNEL_SERVER_URL");
  }

  const [appPort, redisPort, pgPort] = await Promise.all([
    getFreePort(),
    getFreePort(),
    getFreePort(),
  ]);
  const envFilePath = join(serverDir, `.env.channel-e2e-${process.pid}`);

  await writeFile(envFilePath, [
    "POSTGRES_USER=aweb",
    "POSTGRES_PASSWORD=aweb-e2e-test",
    "POSTGRES_DB=aweb",
    `AWEB_PORT=${appPort}`,
    `REDIS_PORT=${redisPort}`,
    `POSTGRES_PORT=${pgPort}`,
    `AWEB_CUSTODY_KEY=${randomHex(64)}`,
    "AWEB_MANAGED_DOMAIN=aweb.local",
    "AWEB_LOG_JSON=true",
  ].join("\n"));

  await runCommand("docker", ["compose", "--env-file", envFilePath, "down", "-v"], {
    cwd: serverDir,
    allowFailure: true,
  });
  await runCommand("docker", ["compose", "--env-file", envFilePath, "up", "--build", "-d"], {
    cwd: serverDir,
  });

  const baseURL = `http://localhost:${appPort}`;
  await waitForHealthyServer(baseURL);
  return { baseURL, envFilePath, managed: true };
}

async function buildAwCli(): Promise<void> {
  await runCommand("make", ["build"], { cwd: cliDir });
}

async function runAwJson<T>(
  workdir: string,
  args: string[],
  extraEnv: Record<string, string> = {},
): Promise<T> {
  const configPath = join(homeDirFor(workdir), ".config", "aw", "config.yaml");
  const result = await runCommand(
    join(cliDir, "aw"),
    args,
    {
      cwd: workdir,
      env: {
        ...stringEnv(process.env),
        HOME: homeDirFor(workdir),
        AW_CONFIG_PATH: configPath,
        ...extraEnv,
      },
    },
  );
  return JSON.parse(result.stdout) as T;
}

function homeDirFor(_workdir: string): string {
  return homeDir;
}

async function runCommand(
  command: string,
  args: string[],
  options: {
    cwd: string;
    env?: Record<string, string>;
    allowFailure?: boolean;
  },
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(command, args, {
      cwd: options.cwd,
      env: options.env,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout: result.stdout.trim(), stderr: result.stderr.trim() };
  } catch (error) {
    if (options.allowFailure) {
      const failed = error as Error & { stdout?: string; stderr?: string };
      return {
        stdout: String(failed.stdout || "").trim(),
        stderr: String(failed.stderr || "").trim(),
      };
    }
    throw error;
  }
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
    await delay(2_000);
  }
  throw new Error(`server at ${baseURL} did not become healthy`);
}

async function dockerAvailable(): Promise<boolean> {
  const result = await runCommand("docker", ["info"], {
    cwd: repoRoot,
    allowFailure: true,
  });
  return result.stderr === "" || !result.stderr.includes("Cannot connect to the Docker daemon");
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

async function sendMail(
  client: APIClient,
  toAlias: string,
  body: string,
  subject: string,
  priority: "low" | "normal" | "high" | "urgent" = "normal",
): Promise<{ message_id: string }> {
  return client.post("/v1/messages", {
    to_alias: toAlias,
    body,
    subject,
    priority,
  });
}

async function fetchInboxForClient(
  client: APIClient,
  unreadOnly: boolean = false,
): Promise<Array<Record<string, string>>> {
  const params = new URLSearchParams({ limit: "50" });
  if (unreadOnly) params.set("unread_only", "true");
  const response = await client.get<{ messages: Array<Record<string, string>> }>(
    `/v1/messages/inbox?${params}`,
  );
  return response.messages;
}

async function fetchInbox(
  recipient: APIClient,
  messageId: string,
  unreadOnly: boolean = false,
): Promise<Record<string, string> | undefined> {
  const inbox = await fetchInboxForClient(recipient, unreadOnly);
  return inbox.find((message) => message.message_id === messageId);
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

async function openChatStream(
  baseURL: string,
  apiKey: string,
  sessionId: string,
  signal: AbortSignal,
): Promise<Response> {
  const deadline = new Date(Date.now() + 5 * 60_000).toISOString();
  const response = await fetch(
    `${baseURL}/v1/chat/sessions/${encodeURIComponent(sessionId)}/stream?deadline=${encodeURIComponent(deadline)}`,
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "text/event-stream",
      },
      signal,
    },
  );
  if (!response.ok) {
    throw new Error(`chat stream failed: ${response.status}`);
  }
  return response;
}
