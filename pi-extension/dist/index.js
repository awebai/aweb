// src/index.ts
import { access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
var require2 = createRequire(import.meta.url);
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
    if (ctx.hasUI) {
      ctx.ui.setStatus("aweb-channel", `aweb channel: ready (${aw.source})`);
    }
  });
}
export {
  awebPiExtension as default
};
