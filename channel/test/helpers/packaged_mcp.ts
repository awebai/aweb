import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

export interface PackagedMCPChild {
  args: string[];
  child: ChildProcessWithoutNullStreams;
  stderr: () => string;
}

export async function launchPackagedMCPChild(channelRoot: string, cwd: string): Promise<PackagedMCPChild> {
  const definition = JSON.parse(readFileSync(join(channelRoot, ".mcp.json"), "utf8")) as {
    mcpServers: { aweb: { command: string; args: string[] } };
  };
  const server = definition.mcpServers.aweb;
  const args = server.args.map((value) => value.replaceAll("${CLAUDE_PLUGIN_ROOT}", channelRoot));

  // Deliberately omit spawn's env option: packaged MCP children must inherit
  // the parent process environment rather than receive a test-only copy.
  const child = spawn(server.command, args, {
    cwd,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  try {
    await withTimeout(
      initializeMCP(child, () => stderr),
      5_000,
      () => `packaged MCP child did not initialize\n${stderr}`,
    );
  } catch (error) {
    child.kill("SIGTERM");
    throw error;
  }
  return { args, child, stderr: () => stderr };
}

function initializeMCP(process: ChildProcessWithoutNullStreams, stderr: () => string): Promise<void> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    process.once("error", reject);
    process.once("exit", (code, signal) => {
      reject(new Error(`MCP child exited before initialization (code=${code}, signal=${signal})\n${stderr()}`));
    });
    process.stdout.setEncoding("utf8");
    process.stdout.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        const message = JSON.parse(line) as { id?: number; error?: unknown };
        if (message.id !== 1) continue;
        if (message.error) {
          reject(new Error(`MCP initialize failed: ${JSON.stringify(message.error)}`));
          return;
        }
        process.stdin.write(`${JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        })}\n`);
        resolve();
      }
    });
    process.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "packaged-mcp-test", version: "1.0.0" },
      },
    })}\n`);
  });
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: () => string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message())), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
