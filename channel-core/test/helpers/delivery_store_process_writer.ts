import { open, stat } from "node:fs/promises";
import { DeliveryStore } from "../../src/channel.js";

const [storePath, readyPath, releasePath, ...messageIDs] = process.argv.slice(2);
if (!storePath || !readyPath || !releasePath || messageIDs.length === 0) {
  throw new Error("usage: delivery_store_process_writer <store> <ready> <release> <message-id>...");
}

const store = await DeliveryStore.load(storePath);
for (const messageID of messageIDs) store.mark(messageID);
const ready = await open(readyPath, "wx", 0o600);
await ready.close();

for (;;) {
  try {
    await stat(releasePath);
    break;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

await store.save();
