// Hosts the packaged aweb Pi extension for one session, as Pi does, and prints
// every message the extension sends to the session as one JSON line. The
// session ends when stdin closes.
import { pathToFileURL } from "node:url";

const [extensionPath, cwd] = process.argv.slice(2);
const { default: awebPiExtension } = await import(pathToFileURL(extensionPath).href);

const handlers = new Map();
const pi = {
  on(event, handler) { handlers.set(event, handler); },
  sendMessage(message) { process.stdout.write(`${JSON.stringify(message)}\n`); },
};
const ctx = { cwd, hasUI: false };

awebPiExtension(pi);
await handlers.get("session_start")({}, ctx);

process.stdin.on("end", async () => {
  await handlers.get("session_shutdown")?.({}, ctx);
  process.exit(0);
});
process.stdin.resume();
