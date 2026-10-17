// Claude Code hook entry for agent activity (docs/agent-activity.md,
// "Emitters"): forwards the hook's event to this session's aweb channel
// plugin. It never writes to stdout, where a hook's output would reach
// Claude, and always exits 0: activity is best-effort and must not affect a turn.
import { activitySocketDir, ancestorPids, forwardHookEvent, hookEventForSocket } from "./activity_socket.js";

const MAX_STDIN_BYTES = 1024 * 1024;

async function readStdin(): Promise<string> {
  let text = "";
  for await (const chunk of process.stdin) {
    text += chunk;
    if (Buffer.byteLength(text, "utf8") > MAX_STDIN_BYTES) return "";
  }
  return text;
}

async function main(): Promise<void> {
  if (typeof process.getuid !== "function") return;
  let payload: unknown;
  try {
    payload = JSON.parse(await readStdin());
  } catch {
    return;
  }
  const event = hookEventForSocket(payload);
  if (event === undefined) return;
  await forwardHookEvent(event, { dir: activitySocketDir(process.getuid()), candidates: ancestorPids() });
}

main().catch(() => {}).finally(() => process.exit(0));
