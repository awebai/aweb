// src/index.ts
import {
  createChannelClient,
  createRegistryResolver,
  formatAwakeningForAgent,
  loadPinStore,
  resolveConfig,
  SenderTrustManager,
  startChannelLoop
} from "@awebai/channel-core";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
var require2 = createRequire(import.meta.url);
var WELCOME_VERSION = "0.1.0";
var WELCOME_STATE_PATH = join(homedir(), ".config", "aw", "pi-welcome.json");
async function isExecutable(path) {
  try {
    await access(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}
async function findOnPath(name) {
  const paths = (process.env.PATH || "").split(delimiter).filter(Boolean);
  for (const dir of paths) {
    const candidate = join(dir, name);
    if (await isExecutable(candidate)) return candidate;
  }
  return void 0;
}
async function resolveBundledAw() {
  try {
    const packageJSONPath = require2.resolve("@awebai/aw/package.json");
    const packageRoot = dirname(packageJSONPath);
    const packageJSON = require2(packageJSONPath);
    const bin = typeof packageJSON.bin === "string" ? packageJSON.bin : packageJSON.bin?.aw;
    if (!bin) return void 0;
    const candidate = join(packageRoot, bin);
    return await isExecutable(candidate) ? candidate : void 0;
  } catch {
    return void 0;
  }
}
async function resolveAw() {
  const pathAw = await findOnPath(process.platform === "win32" ? "aw.cmd" : "aw");
  if (pathAw) return { command: pathAw, source: "path" };
  const bundledAw = await resolveBundledAw();
  if (bundledAw) return { command: bundledAw, source: "bundled" };
  return void 0;
}
function runAw(aw, args, cwd, timeoutMs = 1e4) {
  return new Promise((resolve, reject) => {
    const child = spawn(aw.command, args, {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`aw ${args.join(" ")} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => stdout += chunk);
    child.stderr.on("data", (chunk) => stderr += chunk);
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
function onboardingMessage(reason) {
  return `aweb channel is installed but not ready.

${reason}

To enable aweb awakenings in pi:

1. Initialize this worktree for aweb:

   aw init

2. Then restart pi or run /reload.

Once initialized, incoming aweb mail/chat/control events will wake this pi session with message contents and sender verification status. Use the aw CLI from pi's bash tool to respond.`;
}
function welcomeKey(cwd, teamID, alias) {
  return `${WELCOME_VERSION}:${teamID}:${alias}:${cwd}`;
}
async function loadWelcomeState() {
  try {
    const content = await readFile(WELCOME_STATE_PATH, "utf-8");
    const parsed = JSON.parse(content);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}
async function markWelcomeSeen(key) {
  const state = await loadWelcomeState();
  state.seen = state.seen || {};
  state.seen[key] = (/* @__PURE__ */ new Date()).toISOString();
  await mkdir(dirname(WELCOME_STATE_PATH), { recursive: true });
  await writeFile(WELCOME_STATE_PATH, `${JSON.stringify(state, null, 2)}
`, "utf-8");
}
function welcomeMessage(alias, teamID) {
  return `aweb for Pi is ready.

You are connected as ${alias} in team ${teamID}. This package gives Pi two aweb capabilities: real-time channel awakenings for mail/chat/control events, and the canonical aweb skills for the aw CLI.

First moves:

1. Run \`aw workspace status\` to confirm identity, active team, claims, locks, and presence.
2. Run \`aw mail inbox\` and \`aw chat pending\` before claiming new work.
3. Use mail for handoffs, reviews, and status updates; use chat only when someone is blocked on a near-term answer.
4. When a channel event wakes you, inspect metadata and sender verification before acting.

Skills to load when needed:

- \`aweb-coordination\`: work loop, claims, locks, handoffs, roles, and shared state.
- \`aweb-messaging\`: mail/chat policy, channel awakenings, sender verification, and push events.
- \`aweb-team-membership\`: joining teams, active team, certificates, hosted vs BYOT, custody, addressability, inbound mode, and contacts.

For a full walkthrough, see https://aweb.ai/docs/cli-tutorial/.

If you are unsure what to do next, load \`aweb-coordination\` and start with the session loop there.`;
}
async function sendFirstSessionWelcome(pi, cwd, teamID, alias) {
  const key = welcomeKey(cwd, teamID, alias);
  const state = await loadWelcomeState();
  if (state.seen?.[key]) return;
  await markWelcomeSeen(key);
  pi.sendMessage(
    {
      customType: "aweb-welcome",
      content: welcomeMessage(alias, teamID),
      display: true,
      details: { version: WELCOME_VERSION, team_id: teamID, alias }
    },
    { deliverAs: "followUp", triggerTurn: true }
  );
}
function sendAwakening(pi, awakening) {
  const options = awakening.deliveryIntent === "ambient" ? { deliverAs: "nextTurn" } : awakening.deliveryIntent === "steer" ? { deliverAs: "steer", triggerTurn: true } : { triggerTurn: true };
  pi.sendMessage(
    {
      customType: "aweb-channel",
      content: formatAwakeningForAgent(awakening),
      display: true,
      details: awakening.meta
    },
    options
  );
}
function awebPiExtension(pi) {
  let abortController;
  pi.on("session_shutdown", async () => {
    abortController?.abort();
    abortController = void 0;
  });
  pi.on("session_start", async (_event, ctx) => {
    abortController?.abort();
    abortController = new AbortController();
    const aw = await resolveAw();
    if (!aw) {
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: onboardingMessage("The aw CLI could not be found on PATH and the bundled @awebai/aw dependency could not be resolved."),
        display: true
      });
      return;
    }
    const status = await runAw(aw, ["workspace", "status"], ctx.cwd).catch((error) => ({
      exitCode: 1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error)
    }));
    if (status.exitCode !== 0) {
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: onboardingMessage(`aw is available (${aw.source}) but this directory is not ready.

aw workspace status failed:
${(status.stderr || status.stdout).trim() || "unknown error"}`),
        display: true
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
        content: onboardingMessage(`aw is available (${aw.source}) but aweb channel configuration could not be loaded.

${message}`),
        display: true
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
      config.stableID
    );
    if (ctx.hasUI) {
      const theme = ctx.ui.theme;
      ctx.ui.setStatus("aweb-channel", `${theme.fg("success", "\u2713")} ${theme.fg("dim", "aweb connected")}`);
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
        stableID: config.stableID
      },
      signal,
      onAwakening: (awakening) => sendAwakening(pi, awakening),
      log: (message) => {
        if (ctx.hasUI) ctx.ui.notify(message, "warning");
      }
    }).catch((error) => {
      if (signal.aborted) return;
      const message = error instanceof Error ? error.message : String(error);
      pi.sendMessage({
        customType: "aweb-channel-status",
        content: `aweb channel stopped: ${message}`,
        display: true
      });
      if (ctx.hasUI) {
        const theme = ctx.ui.theme;
        ctx.ui.setStatus("aweb-channel", `${theme.fg("error", "\u2715")} ${theme.fg("dim", "aweb disconnected")}`);
      }
    });
  });
}
export {
  awebPiExtension as default
};
