import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { NotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";
import { childEnvironment } from "./helpers/child_env.js";
import { serverEndpoints } from "./helpers/server_endpoints.js";

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
  team_id: string;
  alias: string;
  aweb_url: string;
}

interface MailSendInfo {
  message_id: string;
  conversation_id?: string;
}

interface ServerHandle {
  awebURL: string;
  awidURL: string;
  managed: boolean;
  projectName?: string;
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

  count(): number {
    return this.items.length;
  }

  snapshot(): Array<{ content: string; meta: Record<string, string> }> {
    return [...this.items];
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
  let domain: string;
  let alice: IdentityInfo;
  let bob: IdentityInfo;
  let mcpClient: Client | undefined;
  let transport: StdioClientTransport | undefined;
  let notifications: NotificationQueue;
  let channelStderr = "";

  beforeAll(async () => {
    const bindRoot = dockerBindRoot();
    await mkdir(bindRoot, { recursive: true });
    tempRoot = await mkdtemp(join(bindRoot, "channel-e2e-"));
    homeDir = join(tempRoot, "home");
    aliceDir = join(tempRoot, "alice");
    bobDir = join(tempRoot, "bob");
    await mkdir(homeDir, { recursive: true });
    await mkdir(aliceDir, { recursive: true });
    await mkdir(bobDir, { recursive: true });

    server = await ensureServer(tempRoot);
    await ensureAwBinary();

    domain = `channel-${Date.now()}.test`;
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
  }, 45_000);

  test("logs live stream outage and reconnects without transport-only notifications", async () => {
    if (!server.managed) return;
    await startChannelIfNeeded();
    await delay(750);

    const setupMailBody = `pre-outage channel readiness ${Date.now()}`;
    const setupMail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", "Stream outage setup", setupMailBody);
    const setupNotification = await notifications.waitFor(
      (item) => item.meta.type === "mail" && item.meta.message_id === setupMail.message_id,
    ).catch((error) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nchannel stderr:\n${channelStderr}`);
    });
    expect(setupNotification.content, JSON.stringify(setupNotification)).toBe(setupMailBody);

    const notificationsBeforeOutage = notifications.count();
    const stderrBeforeOutage = channelStderr.length;
    try {
      await composeAwebService(server, "stop");
      await waitUntil(
        async () => channelStderr.slice(stderrBeforeOutage).includes("aweb: event stream disconnected"),
        90_000,
        () => `event stream disconnect was not logged\n${channelStderr.slice(stderrBeforeOutage)}`,
      );
      expect(channelStderr.slice(stderrBeforeOutage)).not.toContain("TypeError");
    } finally {
      await composeAwebService(server, "start");
    }
    await waitForHealthyServer(server.awebURL);
    await waitUntil(
      async () => channelStderr.slice(stderrBeforeOutage).includes("aweb: event stream reconnected"),
      30_000,
      () => `event stream reconnect was not logged\n${channelStderr.slice(stderrBeforeOutage)}`,
    );
    expect(channelStderr).not.toContain("TypeError: fetch failed");

    const mailBody = `post-reconnect channel mail ${Date.now()}`;
    const mail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", "Mail after reconnect", mailBody);
    const mailNotification = await notifications.waitFor(
      (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
    );
    expect(mailNotification.content, JSON.stringify(mailNotification)).toBe(mailBody);
    expect(mailNotification.meta.from).toBe(alice.address);
    expect(mailNotification.meta.verified).toBe("true");

    const chatBody = `post-reconnect channel chat ${Date.now()}`;
    await sendChatViaAW(homeDir, aliceDir, server.awidURL, "bob", chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toBe(alice.address);
    expect(chatNotification.meta.verified).toBe("true");

    const notificationsDuringCycle = notifications.snapshot().slice(notificationsBeforeOutage);
    expect(notificationsDuringCycle.map((item) => item.meta.type).sort()).toEqual(["chat", "mail"]);
    expect(notificationsDuringCycle.some((item) => item.meta.type === "channel_status"
      || item.meta.stream_state === "disconnected"
      || item.meta.stream_state === "reconnected")).toBe(false);
  }, 240_000);

  test("bridges live aw mail and chat from certificate workspaces into Claude channel notifications", async () => {
    await startChannelIfNeeded();
    await delay(750);

    const mailBody = `channel verified mail ${Date.now()}`;
    const mail = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", "Live mail bridge", mailBody);
    const mailNotification = await notifications.waitFor(
      (item) => item.meta.type === "mail" && item.meta.message_id === mail.message_id,
    );
    expect(mailNotification.content, JSON.stringify(mailNotification)).toBe(mailBody);
    expect(mailNotification.meta.from).toBe(alice.address);
    expect(mailNotification.meta.conversation_id).toBe(mail.conversation_id);
    expect(mailNotification.meta.verified).toBe("true");

    // Presentation is what acknowledges the message, so it is no longer
    // unread once the notification above has been received. The guarantee is
    // ORDERING - never acknowledge before presenting, so a bridge that dies
    // mid-delivery cannot silently consume mail - not that mail stays unread
    // forever. A message still unread after presentation would be re-delivered
    // on every reconnect, which is the replay this design exists to avoid.
    // The assertions above prove it was presented; this proves it was then
    // acknowledged. The acknowledgment is sent after the notification is
    // accepted, so it reaches the server shortly after the notification
    // arrives here, not before.
    const mailIsUnread = async () => {
      const inbox = await runAwJSON<{ messages: Array<{ message_id: string }> }>(
        homeDir,
        bobDir,
        server.awidURL,
        ["--json", "mail", "inbox"],
      );
      return inbox.messages.some((item) => item.message_id === mail.message_id);
    };
    await waitUntil(
      async () => !(await mailIsUnread()),
      10_000,
      () => `mail ${mail.message_id} is still unread after its notification\nchannel stderr:\n${channelStderr}`,
    );
    expect(await mailIsUnread()).toBe(false);

    const chatBody = `channel verified chat ${Date.now()}`;
    await sendChatViaAW(homeDir, aliceDir, server.awidURL, "bob", chatBody);
    const chatNotification = await notifications.waitFor(
      (item) => item.meta.type === "chat" && item.content === chatBody,
    );
    expect(chatNotification.meta.from).toBe(alice.address);
    expect(chatNotification.meta.message_id).toBeTruthy();
    expect(chatNotification.meta.conversation_id).toBeTruthy();
    expect(chatNotification.meta.verified).toBe("true");

    const chatIsPending = async () => {
      const pending = await runAwJSON<{ pending: Array<{ session_id: string; unread_count: number }> }>(
        homeDir,
        bobDir,
        server.awidURL,
        ["--json", "chat", "pending"],
      );
      return pending.pending.some(
        (item) => item.session_id === chatNotification.meta.conversation_id && item.unread_count > 0,
      );
    };
    await waitUntil(
      async () => !(await chatIsPending()),
      10_000,
      () => `chat ${chatNotification.meta.message_id} is still pending after its notification\nchannel stderr:\n${channelStderr}`,
    );
    expect(await chatIsPending()).toBe(false);

    expect(channelStderr).not.toContain("fatal:");
  }, 120_000);

  test("verifies a newly joined local sender's first message to a warm receiver", async () => {
    await startChannelIfNeeded();
    const receiverTransport = transport;
    const warm = await sendMailViaAW(homeDir, aliceDir, server.awidURL, "bob", "Warm receiver", "warm receiver before local join");
    const readiness = await notifications.waitFor(item => item.meta.message_id === warm.message_id);
    expect(readiness.meta.trust_status).toBe("verified");

    const senderDir = join(tempRoot, "finch");
    await mkdir(senderDir);
    const invite = await inviteMember(homeDir, aliceDir, server.awidURL, domain, "devteam");
    await runAwJSON(homeDir, senderDir, server.awidURL, [
      "--json", "id", "team", "accept-invite", invite.token, "--local", "--name", "finch",
    ]);
    await initWorkspace(homeDir, senderDir, server.awidURL, server.awebURL);
    const mail = await sendMailViaAW(homeDir, senderDir, server.awidURL, "bob", "First mail from a new member", "new local member's first mail");
    const first = await notifications.waitFor(item => item.meta.message_id === mail.message_id);
    expect(first.meta.trust_status, JSON.stringify(first)).toBe("verified");
    expect(first.meta.verified).toBe("true");
    expect(transport).toBe(receiverTransport);
  }, 90_000);

  test("verifies a re-initialized same-alias local sender without restarting the receiver", async () => {
    const senderDir = join(tempRoot, "rowan");
    await mkdir(senderDir);
    const invite = await inviteMember(homeDir, aliceDir, server.awidURL, domain, "devteam");
    await runAwJSON(homeDir, senderDir, server.awidURL, [
      "--json", "id", "team", "accept-invite", invite.token, "--local", "--name", "rowan",
    ]);
    await initWorkspace(homeDir, senderDir, server.awidURL, server.awebURL);
    // This is a new local identity, not global rotation or address replacement.
    const roster = await runAwJSON<{ members: Array<{ alias: string; member_did_key: string; identity_scope: string }> }>(
      homeDir, aliceDir, server.awidURL, ["--json", "id", "team", "members", "--namespace", domain, "--team", "devteam"],
    );
    const member = roster.members.find(item => item.alias === "rowan");
    expect(member?.identity_scope).toBe("local");
    const oldDID = member?.member_did_key;
    expect(oldDID).toBeTruthy();
    await startChannelIfNeeded();
    const receiverTransport = transport;
    const before = await sendMailViaAW(homeDir, senderDir, server.awidURL, "bob", "Local before re-init", "local before re-init");
    const first = await notifications.waitFor(item => item.meta.message_id === before.message_id);
    expect(first.meta.trust_status).toBe("verified");
    expect(first.meta.verified).toBe("true");

    // Re-create the sender's lost key through the real BYOT team-controller
    // replacement API, then re-init it. Only this disposable sender is changed.
    await rename(join(senderDir, ".aw", "signing.key"), join(senderDir, ".aw", "signing.key.old"));
    const replacement = await runAwJSON<{ new_did_key: string }>(homeDir, aliceDir, server.awidURL, [
      "--json", "team", "admin", "replace-key", "rowan", "--old-did-key", oldDID!,
      "--home", senderDir, "--generate-new-key", "--aweb-url", server.awebURL,
    ]);
    expect(replacement.new_did_key).not.toBe(oldDID);
    await initWorkspace(homeDir, senderDir, server.awidURL, server.awebURL);
    // The new did:key is a different participant; it cannot continue the old
    // identity's conversation. Start a new signed conversation explicitly.
    const after = await runAwJSON<MailSendInfo>(homeDir, senderDir, server.awidURL, [
      "--json", "mail", "send", "--to", "bob", "--subject", "Local after re-init", "--body", "local after re-init",
    ]);
    const second = await notifications.waitFor(item => item.meta.message_id === after.message_id);
    console.log(`LOCAL_RESPAWN_PROOF ${JSON.stringify({ old_did: oldDID, new_did: replacement.new_did_key,
      before: first.meta.trust_status, after: second.meta.trust_status, verified: second.meta.verified,
      receiver_restarted: transport !== receiverTransport })}`);
    expect(second.meta.trust_status, JSON.stringify(second)).toBe("verified");
    expect(second.meta.verified).toBe("true");
    expect(transport).toBe(receiverTransport);
  }, 90_000);

  async function startChannelIfNeeded(): Promise<void> {
    if (mcpClient) return;

    const command = process.execPath;
    const args = [
      join(channelDir, "node_modules", "tsx", "dist", "cli.mjs"),
      join(channelDir, "src", "index.ts"),
    ];
    transport = new StdioClientTransport({
      command,
      args,
      cwd: bobDir,
      env: {
        ...childEnvironment(),
        HOME: homeDir,
        AWEB_DELIVERY: "channel",
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

  const projectSeed = process.env.AWEB_CHANNEL_E2E_PROJECT
    || `aweb-channel-${basename(tempRoot)}`;
  const projectName = projectSeed
    .toLowerCase().replace(/[^a-z0-9_.-]/g, "-").slice(0, 63);
  if (!projectName || (process.env.AWEB_CHANNEL_E2E_PROJECT
    && projectName !== process.env.AWEB_CHANNEL_E2E_PROJECT)) {
    throw new Error(`invalid bounded Compose project: ${projectSeed}`);
  }

  const envFilePath = join(tempRoot, ".env.integration");
  const overrideFilePath = join(tempRoot, "docker-compose.override.yml");
  const postgresUser = "aweb";
  const postgresPassword = "aweb-e2e-test";
  const postgresDb = "aweb";

  const { awebPort, awidPort, pgPort, redisPort, awebURL, awidURL } =
    await serverEndpoints(repoRoot, projectName, reserveLoopbackPorts);
  await writeFile(envFilePath, [
    `POSTGRES_USER=${postgresUser}`,
    `POSTGRES_PASSWORD=${postgresPassword}`,
    `POSTGRES_DB=${postgresDb}`,
    `POSTGRES_PORT=${pgPort}`,
    `REDIS_PORT=${redisPort}`,
    `AWEB_PORT=${awebPort}`,
    `AWID_PORT=${awidPort}`,
    `AWEB_PUBLIC_ORIGIN=${awebURL}`,
    `AWEB_DISCOVERY_ORIGIN=${awebURL}`,
    `AWID_PUBLIC_REGISTRY_URL=${awidURL}`,
    `AWID_PUBLIC_ORIGINS=${awidURL},http://awid:8010`,
    "AWID_LOG_JSON=true",
    "AWEB_LOG_JSON=true",
    "AWID_RATE_LIMIT_BACKEND=redis",
    "AWID_SERVICE_TOKEN=aweb-channel-e2e-service-token-32-bytes",
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
  await writeFile(overrideFilePath, overrideLines.join("\n"));

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
    return handle;
  } catch (error) {
    await stopServer(handle);
    throw error;
  }
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
  subject: string,
  body: string,
): Promise<MailSendInfo> {
  return runAwJSON(homeDir, workspaceDir, awidURL, [
    "--json",
    "mail",
    "send",
    "--to", to,
    "--subject", subject,
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
      ...childEnvironment(),
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

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}
