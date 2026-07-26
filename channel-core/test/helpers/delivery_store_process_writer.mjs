import { open, stat } from "node:fs/promises";
import { DeliveryStore } from "../../dist/channel.js";

const [storePath, readyPath, releasePath, ...messageIDs] = process.argv.slice(2);
if (!storePath || !readyPath || !releasePath || messageIDs.length === 0) {
  throw new Error("usage: delivery_store_process_writer <store> <ready> <release> <message-id>...");
}

// Only the parent ever writes the release file, so a parent that dies leaves
// nothing that can end this wait. Both exits below are that guard: the first
// covers a parent killed outright, which runs no handler and cannot clean up
// on our behalf, and the second bounds the wait even while a parent is still
// alive but never releasing. Without them the loop spins on a file that will
// never appear, which is how 16 of these survived 23 hours.
const EXIT_PARENT_GONE = 3;
const EXIT_RELEASE_TIMEOUT = 4;

// Comfortably above the barrier test's own timeout so the parent, not the
// child, decides the outcome of any run whose parent is still alive. Lowered
// by the test that proves the deadline fires, which cannot wait two minutes.
const RELEASE_WAIT_TIMEOUT_MS = Number.parseInt(
  process.env.AW_DELIVERY_RELEASE_TIMEOUT_MS ?? "120000",
  10,
);

const store = await DeliveryStore.load(storePath);
for (const messageID of messageIDs) store.mark(messageID);
const ready = await open(readyPath, "wx", 0o600);
await ready.close();

const startingParentPid = process.ppid;
const releaseDeadline = Date.now() + RELEASE_WAIT_TIMEOUT_MS;

for (;;) {
  try {
    await stat(releasePath);
    break;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    // Reparenting is the signal, not a specific new parent: an orphan is
    // adopted by init on some hosts and by a subreaper on others.
    if (process.ppid !== startingParentPid) process.exit(EXIT_PARENT_GONE);
    if (Date.now() >= releaseDeadline) process.exit(EXIT_RELEASE_TIMEOUT);
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

await store.save();
