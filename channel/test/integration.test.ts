import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { NotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";
import {
  processGroupIDForPID,
  stopOwnedProcessTree,
  type OwnedProcessMember,
} from "./helpers/owned_process_group.js";

const execFileAsync = promisify(execFile);
const testDir = dirname(fileURLToPath(import.meta.url));
const channelDir = resolve(testDir, "..");
const repoRoot = resolve(channelDir, "..");
const serverDir = join(repoRoot, "server");
const cliDir = join(repoRoot, "cli", "go");
const awBinary = join(cliDir, "aw");
const skewDirection = process.env.AWEB_SKEW_DIRECTION;
if (skewDirection && skewDirection !== "a-to-b" && skewDirection !== "b-to-a") {
  throw new Error(`AWEB_SKEW_DIRECTION must be a-to-b or b-to-a, got ${skewDirection}`);
}

function emitSkewObservation(
  direction: "a-to-b" | "b-to-a",
  operation: string,
  result: string,
  messageID: string,
  conversationID: string,
  serverRuntime: ServerRuntimeProof | undefined,
): void {
  if (skewDirection === direction) {
    if (!serverRuntime) throw new Error("skew observation lacks server runtime inventory");
    console.log(`AWEB_SKEW_OBSERVATION ${JSON.stringify({
      schema: "aweb.channel-pi-skew-observation.v1",
      component: "channel",
      direction,
      operation,
      result,
      message_id: messageID,
      conversation_id: conversationID,
      server_runtime: serverRuntime,
    })}`);
  }
}

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
  team_id: string;
  alias: string;
  aweb_url: string;
}

interface MailSendInfo {
  message_id: string;
  conversation_id?: string;
}

interface ServerRuntimeProof {
  schema: string;
  constraints_sha256: string;
  python_version: string;
  distributions: Array<{ name: string; version: string }>;
  sha256: string;
}

interface LiveNameHarnessConfig {
  channel_load_spec: string;
  claude_binary: string;
  claude_sha256: string;
  claude_version: string;
  collision_fixture: string;
  credential_env: string;
  evidence_path: string;
  expected_source: string;
  plugin_root: string;
  tgz_sha256: string;
}

interface ServerHandle {
  awebURL: string;
  awidURL: string;
  managed: boolean;
  projectName?: string;
  envFilePath?: string;
  overrideFilePath?: string;
  serverRuntime?: ServerRuntimeProof;
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
  let liveNameEvidencePath = "";

  beforeAll(async () => {
    const supervisedRoot = process.env.AWEB_CHANNEL_LIVE_INTEGRATION_ROOT;
    if (supervisedRoot) {
      tempRoot = resolve(supervisedRoot);
      if (dirname(tempRoot) !== resolve(tmpdir())) {
        throw new Error(`supervised integration root must be directly under TMPDIR: ${tempRoot}`);
      }
      await mkdir(tempRoot);
    } else {
      const bindRoot = dockerBindRoot();
      await mkdir(bindRoot, { recursive: true });
      tempRoot = await mkdtemp(join(bindRoot, "channel-e2e-"));
    }
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
    await publishEncryptionKey(homeDir, aliceDir, server.awidURL);

    bob = await createIdentity(homeDir, bobDir, server.awidURL, "bob", domain);
    const bobInvite = await inviteMember(homeDir, aliceDir, server.awidURL, domain, team);
    await acceptInvite(homeDir, bobDir, server.awidURL, bobInvite.token, "bob");
    await initWorkspace(homeDir, bobDir, server.awidURL, server.awebURL);
    await publishEncryptionKey(homeDir, bobDir, server.awidURL);

    notifications = new NotificationQueue();
  }, 300_000);

  afterAll(async () => {
    let cleanupFailure: unknown;
    let serverCleanupFailed = false;
    try {
      if (transport) await transport.close();
    } catch (error) {
      cleanupFailure = error;
    }
    try {
      await stopServer(server);
    } catch (error) {
      cleanupFailure ||= error;
      serverCleanupFailed = true;
    }
    if (tempRoot && !serverCleanupFailed) {
      try {
        await rm(tempRoot, { recursive: true, force: true });
      } catch (error) {
        cleanupFailure ||= error;
      }
    }
    if (cleanupFailure) throw cleanupFailure;
    if (liveNameEvidencePath) {
      const evidence = JSON.parse(await readFile(liveNameEvidencePath, "utf8")) as Record<string, unknown>;
      evidence.server_cleanup_complete = true;
      await writeFile(liveNameEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    }
  }, 45_000);

  test("reports a live stream outage once and reconnects with durable catch-up guidance", async () => {
    if (!server.managed) return;
    await startChannelIfNeeded();

    await composeAwebService(server, "stop");
    const disconnected = await notifications.waitFor(
      (item) => item.meta.type === "channel_status" && item.meta.stream_state === "disconnected",
      20_000,
    );
    expect(disconnected.content).toMatch(/^aweb: event stream disconnected \([^)]+\) — retrying in \d+s$/);
    expect(disconnected.content).not.toContain("TypeError");

    await composeAwebService(server, "start");
    await waitForHealthyServer(server.awebURL);
    const reconnected = await notifications.waitFor(
      (item) => item.meta.type === "channel_status" && item.meta.stream_state === "reconnected",
      30_000,
    );
    expect(reconnected.content).toBe("aweb: event stream reconnected; check aw mail inbox and aw chat pending for anything missed");
    expect(channelStderr).not.toContain("TypeError: fetch failed");
  }, 120_000);

  test("bridges live aw mail and chat from certificate workspaces into Claude channel notifications", async () => {
    await startChannelIfNeeded();
    await delay(750);

    const mailBody = `channel verified mail ${Date.now()}`;
    const mail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", mailBody);
    const mailNotification = await notifications.waitFor(
      (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
    );
    expect(mailNotification.content, JSON.stringify(mailNotification)).toBe(mailBody);
    expect(mailNotification.meta.from).toBe(alice.address);
    expect(mailNotification.meta.conversation_id).toBe(mail.conversation_id);
    expect(mailNotification.meta.verified).toBe("true");

    const unreadAfterNotification = await runAwJSON<{ messages: Array<{ message_id: string }> }>(
      homeDir,
      bobDir,
      server.awidURL,
      ["--json", "mail", "inbox"],
    );
    // Presentation is what acknowledges the message, so it is no longer
    // unread once the notification above has been received. The guarantee is
    // ORDERING - never acknowledge before presenting, so a bridge that dies
    // mid-delivery cannot silently consume mail - not that mail stays unread
    // forever. A message still unread after presentation would be re-delivered
    // on every reconnect, which is the replay this design exists to avoid.
    // The assertions above prove it was presented; this proves it was then
    // acknowledged exactly once.
    expect(unreadAfterNotification.messages.some((item) => item.message_id === mail.message_id)).toBe(false);

    const chatBody = `channel verified chat ${Date.now()}`;
    await sendChatViaAW(homeDir, aliceDir, server.awidURL, "bob", chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toBe(alice.address);
    expect(chatNotification.meta.message_id).toBeTruthy();
    expect(chatNotification.meta.conversation_id).toBeTruthy();
    expect(chatNotification.meta.verified).toBe("true");
    emitSkewObservation(
      "b-to-a", "sse-chat-presentation", "presented",
      chatNotification.meta.message_id, chatNotification.meta.conversation_id,
      server.serverRuntime,
    );

    if (skewDirection === "a-to-b") {
      await delay(750);
      const pending = await runAw(homeDir, bobDir, server.awidURL, ["chat", "pending"]);
      expect(pending.stdout).not.toContain(chatBody);
      emitSkewObservation(
        "a-to-b", "chat-mark-read", "removed-from-pending",
        chatNotification.meta.message_id, chatNotification.meta.conversation_id,
        server.serverRuntime,
      );
    }

    expect(channelStderr).not.toContain("fatal:");
  }, 120_000);

  test("fresh isolated Claude session wakes through the exact distinct MCP name beside an aweb fixture", async () => {
    const configPath = process.env.AWEB_CHANNEL_NAME_LIVE_CONFIG;
    if (!configPath) return;

    const config = JSON.parse(await readFile(configPath, "utf8")) as LiveNameHarnessConfig;
    liveNameEvidencePath = config.evidence_path;
    requireLoopbackURL(server.awebURL, "aweb");
    requireLoopbackURL(server.awidURL, "awid");
    if (!config.channel_load_spec.trim()) {
      throw new Error("development-channel load spec is empty");
    }
    if (config.expected_source !== "plugin:aweb-channel:aweb-channel") {
      throw new Error(`unexpected Channel notification source: ${config.expected_source}`);
    }
    const credential = process.env[config.credential_env];
    if (!credential) throw new Error(`missing dedicated credential ${config.credential_env}`);

    const claudeRoot = join(tempRoot, "claude-isolated");
    const claudeHome = join(claudeRoot, "home");
    const claudeConfig = join(claudeRoot, "config");
    const xdgConfig = join(claudeRoot, "xdg-config");
    const xdgCache = join(claudeRoot, "xdg-cache");
    const xdgState = join(claudeRoot, "xdg-state");
    await Promise.all([claudeHome, claudeConfig, xdgConfig, xdgCache, xdgState]
      .map((path) => mkdir(path, { recursive: true })));

    const collisionAttempts = join(claudeRoot, "aweb-collision-attempts.jsonl");
    const collisionConfig = join(claudeRoot, "collision-mcp.json");
    const settingsPath = join(claudeRoot, "settings.json");
    const debugPath = join(claudeRoot, "claude-debug.log");
    await writeFile(collisionConfig, `${JSON.stringify({
      mcpServers: {
        aweb: {
          command: process.execPath,
          args: [config.collision_fixture, collisionAttempts],
        },
      },
    }, null, 2)}\n`);
    await writeFile(settingsPath, "{}\n");

    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: claudeHome,
      CLAUDE_CONFIG_DIR: claudeConfig,
      XDG_CONFIG_HOME: xdgConfig,
      XDG_CACHE_HOME: xdgCache,
      XDG_STATE_HOME: xdgState,
      TMPDIR: claudeRoot,
      AW_BIN: awBinary,
      AWID_REGISTRY_URL: server.awidURL,
      AWID_SKIP_DNS_VERIFY: "1",
      [config.credential_env]: credential,
    };
    const args = [
      "--print",
      "--input-format", "stream-json",
      "--output-format", "stream-json",
      "--verbose",
      "--debug-file", debugPath,
      "--settings", settingsPath,
      "--mcp-config", collisionConfig,
      "--strict-mcp-config",
      "--plugin-dir", config.plugin_root,
      "--dangerously-load-development-channels", config.channel_load_spec,
    ];
    const supervisorProcessGroupID = processGroupIDForPID(process.pid);
    if (!supervisorProcessGroupID) throw new Error("live runner has no supervisor process group");
    const claude = spawn(config.claude_binary, args, {
      cwd: bobDir,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    claude.stdout.setEncoding("utf8");
    claude.stderr.setEncoding("utf8");
    claude.stdout.on("data", (chunk) => { stdout += chunk; });
    claude.stderr.on("data", (chunk) => { stderr += chunk; });

    let childCleaned = false;
    try {
      claude.stdin.write(`${JSON.stringify({
        type: "user",
        message: {
          role: "user",
          content: [{ type: "text", text: "Wait for the disposable aweb channel wake." }],
        },
      })}\n`);
      await waitUntil(async () => {
        const attempts = await readFile(collisionAttempts, "utf8").catch(() => "");
        const debug = await readFile(debugPath, "utf8").catch(() => "");
        return attempts.includes('"method":"initialize"')
          && debug.includes("aweb-channel")
          && /mcp|MCP/.test(debug);
      }, 45_000, () => `both MCP initialize attempts were not observed\n${stderr}`);

      const marker = `aweb-abbs-live-${Date.now()}`;
      const mail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", marker);
      const expectedSource = config.expected_source;
      await waitUntil(
        async () => stdout.includes(marker) && stdout.includes(expectedSource),
        60_000,
        () => `fresh Claude process did not present exact-name wake ${mail.message_id}\n${stdout}\n${stderr}`,
      );
      expect(stdout.match(new RegExp(marker, "g"))?.length).toBe(1);
      expect(stdout).not.toMatch(/plugin:aweb-channel:aweb(?![A-Za-z0-9_-])/);

      const processTreeProof = await stopOwnedProcessTree(claude, supervisorProcessGroupID);
      requireObservedMCPChildren(
        processTreeProof.observed_members,
        claude.pid,
        config.collision_fixture,
        join(config.plugin_root, "dist", "index.js"),
      );
      childCleaned = true;
      await writeFile(config.evidence_path, `${JSON.stringify({
        schema: "aweb.channel-name-live-proof.v1",
        candidate_tgz_sha256: config.tgz_sha256,
        channel_source: expectedSource,
        claude_binary: config.claude_binary,
        claude_sha256: config.claude_sha256,
        claude_version: config.claude_version,
        collision_fixture_name: "aweb",
        collision_initialize_observed: true,
        plugin_initialize_observed: true,
        message_id: mail.message_id,
        marker,
        owned_process_pids: processTreeProof.observed_pids,
        process_tree_sigkill_required: processTreeProof.sigkill_required,
        process_tree_termination_proven: processTreeProof.termination_proven,
        child_cleanup_complete: true,
      }, null, 2)}\n`);
    } finally {
      if (!childCleaned) {
        await stopOwnedProcessTree(claude, supervisorProcessGroupID).catch(() => {});
      }
    }
  }, 180_000);

  async function startChannelIfNeeded(): Promise<void> {
    if (mcpClient) return;

    const exactPackageRoot = process.env.AWEB_CHANNEL_PACKAGE_ROOT;
    const command = process.execPath;
    const args = exactPackageRoot
      ? [join(resolve(exactPackageRoot), "dist", "index.js")]
      : [
          join(channelDir, "node_modules", "tsx", "dist", "cli.mjs"),
          join(channelDir, "src", "index.ts"),
        ];
    transport = new StdioClientTransport({
      command,
      args,
      cwd: bobDir,
      env: {
        ...stringEnv(process.env),
        HOME: homeDir,
        AW_BIN: awBinary,
        AWID_REGISTRY_URL: server.awidURL,
        AWID_SKIP_DNS_VERIFY: "1",
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

function dockerBindRoot(): string {
  const rawRoot = process.env.AWEB_DOCKER_BIND_ROOT || tmpdir();
  if (!rawRoot.startsWith("/")) {
    throw new Error(`AWEB_DOCKER_BIND_ROOT must be absolute: ${rawRoot}`);
  }
  return resolve(rawRoot);
}

function dockerPublishedHost(): string {
  const host = process.env.AWEB_DOCKER_PUBLISHED_HOST || "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "aweb-docker.test") {
    throw new Error(`AWEB_DOCKER_PUBLISHED_HOST has unsupported fixed value ${host}`);
  }
  return host;
}

function requireLoopbackURL(rawURL: string, label: string): void {
  const url = new URL(rawURL);
  const allowed = new Set(["127.0.0.1", "::1", dockerPublishedHost()]);
  if (url.protocol !== "http:" || !allowed.has(url.hostname)) {
    throw new Error(`${label} live-proof endpoint must use the fixed Docker host, got ${rawURL}`);
  }
}

async function waitUntil(
  predicate: () => Promise<boolean>,
  timeoutMs: number,
  failure: () => string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(100);
  }
  throw new Error(failure());
}

function requireObservedMCPChildren(
  members: OwnedProcessMember[],
  leaderPID: number | undefined,
  collisionFixture: string,
  pluginEntry: string,
): void {
  if (!leaderPID || !members.some(({ pid }) => pid === leaderPID)) {
    throw new Error(`owned process tree did not contain Claude leader ${leaderPID}`);
  }
  const commands = members.map(({ command }) => command);
  if (!commands.some((command) => command.includes(resolve(collisionFixture)))) {
    throw new Error(`owned process tree did not contain collision fixture: ${JSON.stringify(commands)}`);
  }
  if (!commands.some((command) => command.includes(resolve(pluginEntry)))) {
    throw new Error(`owned process tree did not contain packaged Channel MCP: ${JSON.stringify(commands)}`);
  }
}

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

  const [awebPort, awidPort, pgPort, redisPort] = await reserveLoopbackPorts(4);
  const projectSeed = process.env.AWEB_SKEW_PROJECT_TOKEN
    || `aweb-skew-${basename(tempRoot)}-${process.env.AWEB_SKEW_CELL_ID || "channel"}`;
  const projectName = projectSeed
    .toLowerCase().replace(/[^a-z0-9_.-]/g, "-").slice(0, 63);
  if (!projectName || (process.env.AWEB_SKEW_PROJECT_TOKEN
    && projectName !== process.env.AWEB_SKEW_PROJECT_TOKEN)) {
    throw new Error(`invalid bounded skew Compose project: ${projectSeed}`);
  }

  const envFilePath = join(tempRoot, ".env.integration");
  const overrideFilePath = join(tempRoot, "docker-compose.override.yml");
  const postgresUser = "aweb";
  const postgresPassword = "aweb-e2e-test";
  const postgresDb = "aweb";

  const publishedHost = dockerPublishedHost();
  await writeFile(envFilePath, [
    `POSTGRES_USER=${postgresUser}`,
    `POSTGRES_PASSWORD=${postgresPassword}`,
    `POSTGRES_DB=${postgresDb}`,
    `POSTGRES_PORT=${pgPort}`,
    `REDIS_PORT=${redisPort}`,
    `AWEB_PORT=${awebPort}`,
    `AWID_PORT=${awidPort}`,
    `AWEB_PUBLIC_ORIGIN=http://${publishedHost}:${awebPort}`,
    `AWEB_DISCOVERY_ORIGIN=http://${publishedHost}:${awebPort}`,
    `AWID_PUBLIC_REGISTRY_URL=http://${publishedHost}:${awidPort}`,
    "AWID_LOG_JSON=true",
    "AWEB_LOG_JSON=true",
    "AWID_RATE_LIMIT_BACKEND=redis",
    "AWID_SKIP_DNS_VERIFY=1",
  ].join("\n"));

  const overrideLines = [
    "services:",
    "  redis:",
    "    ports:",
    '      - "${REDIS_PORT}:6379"',
    "  postgres:",
    "    ports:",
    '      - "${POSTGRES_PORT}:5432"',
  ];
  const exactServerWheel = process.env.AWEB_SKEW_SERVER_WHEEL;
  const exactServerSHA = process.env.AWEB_SKEW_SERVER_SHA256;
  const exactServerVersion = process.env.AWEB_SKEW_SERVER_VERSION;
  const exactServerConstraints = process.env.AWEB_SKEW_SERVER_CONSTRAINTS;
  const exactServerConstraintsSHA = process.env.AWEB_SKEW_SERVER_CONSTRAINTS_SHA256;
  const exactInputs = [
    exactServerWheel, exactServerSHA, exactServerVersion,
    exactServerConstraints, exactServerConstraintsSHA,
  ];
  if (exactInputs.some(Boolean)) {
    if (exactInputs.some((value) => !value)) {
      throw new Error("set the exact server wheel, version, constraints, and both SHA-256 values together");
    }
    const wheel = await readFile(resolve(exactServerWheel!));
    const digest = createHash("sha256").update(wheel).digest("hex");
    if (digest !== exactServerSHA) {
      throw new Error(`exact server wheel sha256 ${digest} does not equal ${exactServerSHA}`);
    }
    const constraints = await readFile(resolve(exactServerConstraints!));
    const constraintsDigest = createHash("sha256").update(constraints).digest("hex");
    if (constraintsDigest !== exactServerConstraintsSHA) {
      throw new Error(
        `server constraints sha256 ${constraintsDigest} does not equal ${exactServerConstraintsSHA}`,
      );
    }
    const buildRoot = join(tempRoot, "exact-server-wheel");
    const wheelName = basename(exactServerWheel!);
    await mkdir(buildRoot, { recursive: true });
    await writeFile(join(buildRoot, wheelName), wheel);
    await writeFile(join(buildRoot, "server-runtime-constraints.txt"), constraints);
    await writeFile(
      join(buildRoot, "server_runtime_inventory.py"),
      await readFile(join(repoRoot, "scripts", "e2e", "server_runtime_inventory.py")),
    );
    await writeFile(join(buildRoot, "Dockerfile"), [
      "FROM python:3.12-slim",
      "RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*",
      `COPY ${JSON.stringify(wheelName)} /tmp/${wheelName}`,
      "COPY server-runtime-constraints.txt /tmp/server-runtime-constraints.txt",
      "COPY server_runtime_inventory.py /usr/local/bin/aweb-skew-runtime-inventory",
      `ENV AWEB_SKEW_SERVER_CONSTRAINTS_SHA256=${exactServerConstraintsSHA}`,
      `RUN python -m pip install --no-cache-dir --constraint /tmp/server-runtime-constraints.txt /tmp/${wheelName}`,
      'CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]',
    ].join("\n"));
    overrideLines.push(
      "  aweb:",
      "    build:",
      `      context: ${JSON.stringify(buildRoot)}`,
      '      dockerfile: "Dockerfile"',
    );
  }
  await writeFile(overrideFilePath, overrideLines.join("\n"));

  const awidURL = `http://${publishedHost}:${awidPort}`;
  const awebURL = `http://${publishedHost}:${awebPort}`;
  const handle: ServerHandle = {
    awebURL,
    awidURL,
    managed: true,
    projectName,
    envFilePath,
    overrideFilePath,
  };
  try {
    await runCommand("docker", [
      "compose",
      "-p", projectName,
      "-f", join(serverDir, "docker-compose.yml"),
      "-f", overrideFilePath,
      "--env-file", envFilePath,
      "up",
      "-d",
      "--build",
    ], { cwd: serverDir, timeoutMs: 300_000 });
    await waitForHealthyServer(awidURL);
    await waitForHealthyServer(awebURL);
    if (exactServerWheel) {
      handle.serverRuntime = await captureServerRuntime(
        handle, exactServerConstraintsSHA!, exactServerVersion!,
      );
    }
    return handle;
  } catch (error) {
    await stopServer(handle);
    throw error;
  }
}

async function captureServerRuntime(
  server: ServerHandle,
  expectedConstraintsSHA: string,
  expectedVersion: string,
): Promise<ServerRuntimeProof> {
  const result = await runCommand("docker", [
    "compose",
    "-p", server.projectName!,
    "-f", join(serverDir, "docker-compose.yml"),
    "-f", server.overrideFilePath!,
    "--env-file", server.envFilePath!,
    "exec", "-T", "aweb", "python", "/usr/local/bin/aweb-skew-runtime-inventory",
  ], { cwd: serverDir, timeoutMs: 30_000 });
  const runtime = JSON.parse(result.stdout) as ServerRuntimeProof;
  const aweb = runtime.distributions?.find((item) => item.name === "aweb");
  if (
    runtime.schema !== "aweb.server-runtime-inventory.v1"
    || runtime.constraints_sha256 !== expectedConstraintsSHA
    || !/^[0-9a-f]{64}$/.test(runtime.sha256)
    || aweb?.version !== expectedVersion
  ) {
    throw new Error("exact service returned an invalid server runtime inventory");
  }
  return runtime;
}

async function composeAwebService(server: ServerHandle, action: "start" | "stop"): Promise<void> {
  if (!server.managed || !server.projectName || !server.envFilePath || !server.overrideFilePath) return;
  await runCommand("docker", [
    "compose",
    "-p", server.projectName,
    "-f", join(serverDir, "docker-compose.yml"),
    "-f", server.overrideFilePath,
    "--env-file", server.envFilePath,
    action,
    "aweb",
  ], { cwd: serverDir, timeoutMs: 120_000 });
}

async function stopServer(server: ServerHandle | undefined): Promise<void> {
  if (!server) return;

  if (server.managed && server.projectName && server.envFilePath && server.overrideFilePath) {
    const compose = [
      "compose",
      "-p", server.projectName,
      "-f", join(serverDir, "docker-compose.yml"),
      "-f", server.overrideFilePath,
      "--env-file", server.envFilePath,
      "down",
      "-v",
      "--rmi", "local",
      "--remove-orphans",
    ];
    let cleanupFailure: unknown;
    try {
      await runCommand("docker", compose, { cwd: serverDir, timeoutMs: 120_000 });
    } catch (error) {
      cleanupFailure = error;
    }
    const leftovers: string[] = [];
    for (const resource of ["container", "volume", "network", "image"]) {
      const listArgs = resource === "container"
        ? [resource, "ls", "-aq"] : [resource, "ls", "-q"];
      try {
        const remaining = await runCommand(
          "docker", listArgs.concat(["--filter",
            `label=com.docker.compose.project=${server.projectName}`]),
          { cwd: serverDir, timeoutMs: 30_000 },
        );
        if (remaining.stdout) leftovers.push(`${resource}:${remaining.stdout}`);
      } catch (error) {
        cleanupFailure ||= error;
      }
    }
    if (leftovers.length) {
      cleanupFailure ||= new Error(
        `Compose project ${server.projectName} still owns resources: ${leftovers.join(",")}`,
      );
    }
    if (cleanupFailure) throw cleanupFailure;
    await rm(server.envFilePath, { force: true });
    await rm(server.overrideFilePath, { force: true });
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
    "--global",
    "--name", alias,
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

async function publishEncryptionKey(
  homeDir: string,
  workspaceDir: string,
  awidURL: string,
): Promise<void> {
  await runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "id",
    "encryption-key",
    "setup",
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

async function reserveLoopbackPorts(count: number): Promise<number[]> {
  const servers = Array.from({ length: count }, () => createServer());
  try {
    const ports = await Promise.all(servers.map((server) => new Promise<number>((resolvePort, rejectPort) => {
      server.once("error", rejectPort);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (!address || typeof address === "string") {
          rejectPort(new Error("failed to reserve loopback port"));
        } else {
          resolvePort(address.port);
        }
      });
    })));
    return ports;
  } finally {
    await Promise.all(servers.map((server) => new Promise<void>((resolveClose, rejectClose) => {
      server.close((error) => error ? rejectClose(error) : resolveClose());
    })));
  }
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
