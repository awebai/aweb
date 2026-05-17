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
import { access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
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
