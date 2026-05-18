import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  createChannelClient,
  createRegistryResolver,
  formatAwakeningForAgent,
  loadPinStore,
  resolveConfig,
  SenderTrustManager,
  startChannelLoop,
  type ChannelAwakening,
} from "@awebai/channel-core";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";

interface AwResolution {
  command: string;
  source: "path" | "bundled";
}

interface AwCommandResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

const require = createRequire(import.meta.url);
const WELCOME_VERSION = "0.1.0";
const WELCOME_STATE_PATH = join(homedir(), ".config", "aw", "pi-welcome.json");

interface WelcomeState {
  seen?: Record<string, string>;
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function findOnPath(name: string): Promise<string | undefined> {
  const paths = (process.env.PATH || "").split(delimiter).filter(Boolean);
  for (const dir of paths) {
    const candidate = join(dir, name);
    if (await isExecutable(candidate)) return candidate;
  }
  return undefined;
}

async function resolveBundledAw(): Promise<string | undefined> {
  try {
    const packageJSONPath = require.resolve("@awebai/aw/package.json");
    const packageRoot = dirname(packageJSONPath);
    const packageJSON = require(packageJSONPath) as { bin?: string | Record<string, string> };
    const bin = typeof packageJSON.bin === "string" ? packageJSON.bin : packageJSON.bin?.aw;
    if (!bin) return undefined;
    const candidate = join(packageRoot, bin);
    return (await isExecutable(candidate)) ? candidate : undefined;
  } catch {
    return undefined;
  }
}

async function resolveAw(): Promise<AwResolution | undefined> {
  const pathAw = await findOnPath(process.platform === "win32" ? "aw.cmd" : "aw");
  if (pathAw) return { command: pathAw, source: "path" };

  const bundledAw = await resolveBundledAw();
  if (bundledAw) return { command: bundledAw, source: "bundled" };

  return undefined;
}

function runAw(aw: AwResolution, args: string[], cwd: string, timeoutMs = 10_000): Promise<AwCommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(aw.command, args, {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`aw ${args.join(" ")} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      resolve({ exitCode, stdout, stderr });
    });
  });
}

function onboardingMessage(reason: string): string {
  return `aweb channel is installed but not ready.\n\n${reason}\n\nTo enable aweb awakenings in pi:\n\n1. Initialize this worktree for aweb:\n\n   aw init\n\n2. Then restart pi or run /reload.\n\nOnce initialized, incoming aweb mail/chat/control events will wake this pi session with message contents and sender verification status. Use the aw CLI from pi's bash tool to respond.`;
}

function welcomeKey(cwd: string, teamID: string, alias: string): string {
  return `${WELCOME_VERSION}:${teamID}:${alias}:${cwd}`;
}

async function loadWelcomeState(): Promise<WelcomeState> {
  try {
    const content = await readFile(WELCOME_STATE_PATH, "utf-8");
    const parsed = JSON.parse(content) as WelcomeState;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function markWelcomeSeen(key: string): Promise<void> {
  const state = await loadWelcomeState();
  state.seen = state.seen || {};
  state.seen[key] = new Date().toISOString();
  await mkdir(dirname(WELCOME_STATE_PATH), { recursive: true });
  await writeFile(WELCOME_STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, "utf-8");
}

function welcomeMessage(alias: string, teamID: string): string {
  return `aweb for Pi is ready.\n\nYou are connected as ${alias} in team ${teamID}. This package gives Pi two aweb capabilities: real-time channel awakenings for mail/chat/control events, and the canonical aweb skills for using the aw CLI well.\n\nFirst moves:\n\n1. Run \`aw workspace status\` to confirm identity, active team, claims, locks, and presence.\n2. Run \`aw mail inbox\` and \`aw chat pending\` before claiming new work.\n3. Use mail for handoffs, reviews, and status updates; use chat only when someone is blocked on a near-term answer.\n4. When a channel event wakes you, inspect metadata and sender verification before acting.\n\nSkills to load when needed:\n\n- \`aweb-coordination\`: work loop, claims, locks, handoffs, roles, and shared state.\n- \`aweb-messaging\`: mail/chat policy, channel awakenings, sender verification, and push events.\n- \`aweb-team-membership\`: joining teams, active team, certificates, hosted vs BYOT, custody, reachability, and contacts.\n\nFor a full walkthrough, see https://aweb.ai/docs/cli-tutorial/.\n\nIf you are unsure what to do next, load \`aweb-coordination\` and start with the session loop there.`;
}

async function sendFirstSessionWelcome(pi: ExtensionAPI, cwd: string, teamID: string, alias: string): Promise<void> {
  const key = welcomeKey(cwd, teamID, alias);
  const state = await loadWelcomeState();
  if (state.seen?.[key]) return;
  await markWelcomeSeen(key);
  pi.sendMessage(
    {
      customType: "aweb-welcome",
      content: welcomeMessage(alias, teamID),
      display: true,
      details: { version: WELCOME_VERSION, team_id: teamID, alias },
    },
    { deliverAs: "followUp", triggerTurn: true },
  );
}

function sendAwakening(pi: ExtensionAPI, awakening: ChannelAwakening): void {
  const options = awakening.deliveryIntent === "ambient"
    ? { deliverAs: "nextTurn" as const }
    : awakening.deliveryIntent === "steer"
      ? { deliverAs: "steer" as const, triggerTurn: true }
      : { triggerTurn: true };

  pi.sendMessage(
    {
      customType: "aweb-channel",
      content: formatAwakeningForAgent(awakening),
      display: true,
      details: awakening.meta,
    },
    options,
  );
}

export default function awebPiExtension(pi: ExtensionAPI) {
  let abortController: AbortController | undefined;

  pi.on("session_shutdown", async () => {
    abortController?.abort();
    abortController = undefined;
  });

  pi.on("session_start", async (_event, ctx) => {
    abortController?.abort();
    abortController = new AbortController();

    const aw = await resolveAw();
    if (!aw) {
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: onboardingMessage("The aw CLI could not be found on PATH and the bundled @awebai/aw dependency could not be resolved."),
        display: true,
      });
      return;
    }

    const status = await runAw(aw, ["workspace", "status"], ctx.cwd).catch((error) => ({
      exitCode: 1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
    }));

    if (status.exitCode !== 0) {
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: onboardingMessage(`aw is available (${aw.source}) but this directory is not ready.\n\naw workspace status failed:\n${(status.stderr || status.stdout).trim() || "unknown error"}`),
        display: true,
      });
      return;
    }

    let config;
    try {
      config = await resolveConfig(ctx.cwd);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: onboardingMessage(`aw is available (${aw.source}) but aweb channel configuration could not be loaded.\n\n${message}`),
        display: true,
      });
      return;
    }

    const client = createChannelClient(config);
    const pinStore = await loadPinStore();
    const registry = createRegistryResolver(config.registryURL);
    const trust = new SenderTrustManager(
      client,
      registry,
      config.teamID,
      config.did,
      config.stableID,
    );

    if (ctx.hasUI) {
      ctx.ui.setStatus("aweb-channel", `aweb channel: ready (${aw.source})`);
    }

    void sendFirstSessionWelcome(pi, ctx.cwd, config.teamID, config.alias).catch((error) => {
      if (ctx.hasUI) ctx.ui.notify(`aweb welcome skipped: ${error instanceof Error ? error.message : String(error)}`, "warning");
    });

    const signal = abortController.signal;
    void startChannelLoop({
      client,
      pinStore,
      trust,
      self: {
        alias: config.alias,
        address: config.address,
        did: config.did,
        stableID: config.stableID,
      },
      signal,
      onAwakening: (awakening) => sendAwakening(pi, awakening),
      log: (message) => {
        if (ctx.hasUI) ctx.ui.notify(message, "warning");
      },
    }).catch((error) => {
      if (signal.aborted) return;
      const message = error instanceof Error ? error.message : String(error);
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: `aweb channel stopped: ${message}`,
        display: true,
      });
      if (ctx.hasUI) ctx.ui.setStatus("aweb-channel", "aweb channel: stopped");
    });
  });
}
