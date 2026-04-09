import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
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
import { streamAgentEvents } from "../src/api/events.js";
import { resolveConfig } from "../src/config.js";

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

interface IdentityInfo {
  address: string;
  did_aw: string;
  did_key: string;
}

interface InviteInfo {
  token: string;
}

interface InitInfo {
  team_address: string;
  alias: string;
  aweb_url: string;
}

interface MailSendInfo {
  message_id: string;
}

interface ServerHandle {
  awebURL: string;
  awidURL: string;
  managed: boolean;
  envFilePath?: string;
  overrideFilePath?: string;
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
  let alice: IdentityInfo;
  let bob: IdentityInfo;
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

    const domain = `channel-${Date.now()}.test`;
    const team = "devteam";

    alice = await createIdentity(homeDir, aliceDir, server.awidURL, "alice", domain);
    await createTeam(homeDir, aliceDir, server.awidURL, domain, team);
    const aliceInvite = await inviteMember(homeDir, aliceDir, server.awidURL, domain, team);
    await acceptInvite(homeDir, aliceDir, server.awidURL, aliceInvite.token, "alice");
    await initWorkspace(homeDir, aliceDir, server.awidURL, server.awebURL);

    bob = await createIdentity(homeDir, bobDir, server.awidURL, "bob", domain);
    const bobInvite = await inviteMember(homeDir, aliceDir, server.awidURL, domain, team);
    await acceptInvite(homeDir, bobDir, server.awidURL, bobInvite.token, "bob");
    await initWorkspace(homeDir, bobDir, server.awidURL, server.awebURL);

    notifications = new NotificationQueue();
  }, 300_000);

  afterAll(async () => {
    await transport?.close().catch(() => {});
    await stopServer(server);
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }, 120_000);

  test("bridges live aw mail and chat from certificate workspaces into Claude channel notifications", async () => {
    await startChannelIfNeeded();
    await delay(750);

    const mailBody = `channel verified mail ${Date.now()}`;
    const mail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", mailBody);
    let mailNotification;
    try {
      mailNotification = await notifications.waitFor(
        (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
      );
    } catch (error) {
      const inbox = await runAw(homeDir, bobDir, server.awidURL, [
        "--json",
        "mail",
        "inbox",
      ]).catch(() => ({ stdout: "", stderr: "" }));
      const directEvents = await collectDirectEvents(bobDir).catch(() => []);
      throw new Error(
        `${String(error)}\nchannel stderr:\n${channelStderr || "(empty)"}\n` +
        `bob inbox stdout:\n${inbox.stdout || "(empty)"}\n` +
        `bob inbox stderr:\n${inbox.stderr || "(empty)"}\n` +
        `direct events:\n${directEvents.length > 0 ? directEvents.join("\n") : "(none)"}`,
      );
    }
    expect(mailNotification.content).toBe(mailBody);
    expect(mailNotification.meta.from).toBe("alice");
    expect(mailNotification.meta.verified).toBe("true");

    const chatBody = `channel verified chat ${Date.now()}`;
    await sendChatViaAW(homeDir, aliceDir, server.awidURL, "bob", chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toBe("alice");
    expect(chatNotification.meta.verified).toBe("true");

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
        AWID_REGISTRY_URL: server.awidURL,
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
  const providedAwebURL = process.env.AWEB_TEST_URL;
  const providedAwidURL = process.env.AWID_TEST_URL;
  if (providedAwebURL || providedAwidURL) {
    if (!providedAwebURL || !providedAwidURL) {
      throw new Error("set both AWEB_TEST_URL and AWID_TEST_URL, or neither");
    }
    await waitForHealthyServer(providedAwidURL);
    await waitForHealthyServer(providedAwebURL);
    return { awebURL: providedAwebURL, awidURL: providedAwidURL, managed: false };
  }

  if (!(await dockerAvailable())) {
    throw new Error("Docker daemon unavailable; start Docker or set AWEB_TEST_URL/AWID_TEST_URL");
  }

  const [awebPort, awidPort, pgPort, redisPort] = await Promise.all([
    getFreePort(),
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
    `AWEB_PORT=${awebPort}`,
    `AWID_PORT=${awidPort}`,
    "AWID_LOG_JSON=true",
    "AWEB_LOG_JSON=true",
    "AWID_RATE_LIMIT_BACKEND=redis",
    "AWID_SKIP_DNS_VERIFY=1",
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
  ], { cwd: serverDir, allowFailure: true, timeoutMs: 120_000 });

  await runCommand("docker", [
    "compose",
    "-f", join(serverDir, "docker-compose.yml"),
    "-f", overrideFilePath,
    "--env-file", envFilePath,
    "up",
    "-d",
    "--build",
  ], { cwd: serverDir, timeoutMs: 300_000 });

  const awidURL = `http://127.0.0.1:${awidPort}`;
  const awebURL = `http://127.0.0.1:${awebPort}`;
  try {
    await waitForHealthyServer(awidURL);
    await waitForHealthyServer(awebURL);
  } catch (error) {
    await stopServer({
      awebURL,
      awidURL,
      managed: true,
      envFilePath,
      overrideFilePath,
    });
    throw error;
  }

  return {
    awebURL,
    awidURL,
    managed: true,
    envFilePath,
    overrideFilePath,
  };
}

async function stopServer(server: ServerHandle | undefined): Promise<void> {
  if (!server) return;

  if (server.managed && server.envFilePath && server.overrideFilePath) {
    await runCommand("docker", [
      "compose",
      "-f", join(serverDir, "docker-compose.yml"),
      "-f", server.overrideFilePath,
      "--env-file", server.envFilePath,
      "down",
      "-v",
    ], { cwd: serverDir, allowFailure: true, timeoutMs: 120_000 });
    await rm(server.envFilePath, { force: true }).catch(() => {});
    await rm(server.overrideFilePath, { force: true }).catch(() => {});
  }
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

async function createIdentity(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  name: string,
  domain: string,
): Promise<IdentityInfo> {
  return runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "id",
    "create",
    "--name", name,
    "--domain", domain,
    "--registry", awidURL,
    "--skip-dns-verify",
  ]);
}

async function createTeam(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  domain: string,
  team: string,
): Promise<void> {
  await runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "id",
    "team",
    "create",
    "--namespace", domain,
    "--name", team,
    "--registry", awidURL,
  ]);
}

async function inviteMember(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  domain: string,
  team: string,
): Promise<InviteInfo> {
  return runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "id",
    "team",
    "invite",
    "--namespace", domain,
    "--team", team,
  ]);
}

async function acceptInvite(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  token: string,
  alias: string,
): Promise<void> {
  await runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "id",
    "team",
    "accept-invite",
    token,
    "--alias", alias,
  ]);
}

async function initWorkspace(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  awebURL: string,
): Promise<InitInfo> {
  return runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "init",
    "--url", awebURL,
  ]);
}

async function sendMailViaAW(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  to: string,
  body: string,
): Promise<MailSendInfo> {
  return runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "mail",
    "send",
    "--to", to,
    "--body", body,
  ]);
}

async function sendChatViaAW(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  to: string,
  body: string,
): Promise<void> {
  await runAw(homeDir, workspaceDir, awidURL, [
    "chat",
    "send-and-leave",
    to,
    body,
  ]);
}

async function runAwJSON<T>(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  args: string[],
): Promise<T> {
  const result = await runAw(homeDir, workspaceDir, awidURL, args);
  return JSON.parse(extractJSONObject(result.stdout)) as T;
}

async function runAw(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  const result = await execFileAsync(awBinary, args, {
    cwd: workspaceDir,
    encoding: "utf8",
    env: {
      ...stringEnv(process.env),
      HOME: homeDir,
      AW_CONFIG_PATH: join(homeDir, ".config", "aw", "config.yaml"),
      AWID_REGISTRY_URL: awidURL,
      AWID_SKIP_DNS_VERIFY: "1",
    },
    maxBuffer: 10 * 1024 * 1024,
  });
  return {
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

function extractJSONObject(output: string): string {
  const start = output.indexOf("{");
  const end = output.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    throw new Error(`expected JSON object in output:\n${output}`);
  }
  return output.slice(start, end + 1);
}

async function collectDirectEvents(workdir: string, timeoutMs: number = 5_000): Promise<string[]> {
  const cfg = await resolveConfig(workdir);
  const client = new APIClient(cfg.baseURL, {
    did: cfg.did,
    signingKey: cfg.signingKey,
    teamAddress: cfg.teamAddress,
    teamCertificateHeader: cfg.teamCertificateHeader,
  });
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  const events: string[] = [];
  try {
    for await (const event of streamAgentEvents(client, abort.signal)) {
      events.push(JSON.stringify(event));
      if (event.type !== "connected") {
        break;
      }
    }
  } finally {
    clearTimeout(timer);
  }
  return events;
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

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}
