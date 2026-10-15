import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { lock } from "proper-lockfile";
import type { EventStreamObserver } from "./api/events.js";

export interface ReceiveReceiptOptions {
  identityHome: string;
  kind: "claude-channel" | "pi-extension";
  did: string;
  stableID?: string;
  onError?: (message: string) => void;
}

/** Local evidence of successful server reads, never a timer-based health claim. */
export class ReceiveStreamReceipt implements EventStreamObserver {
  private pending: Promise<void> = Promise.resolve();
  private openedAt: number | undefined;
  private lastRead: number | undefined;
  private reportedError = false;

  constructor(private readonly options: ReceiveReceiptOptions) {}

  onRead = (openedAt: number, readAt: number): void => {
    if (this.openedAt === openedAt && this.lastRead !== undefined && readAt - this.lastRead < 30_000) return;
    this.openedAt = openedAt;
    this.lastRead = readAt;
    // Capture the read time now. Slow disk I/O must not fabricate a fresher beat.
    const receipt = {
      v: 1, kind: this.options.kind, did: this.options.did,
      ...(this.options.stableID ? { stable_id: this.options.stableID } : {}),
      pid: process.pid, opened_at: new Date(openedAt).toISOString(), heartbeat_at: new Date(readAt).toISOString(),
    };
    this.enqueue(async (directory, path) => {
      const temporary = join(directory, `.stream-${process.pid}-${randomUUID()}.tmp`);
      try {
        await writeFile(temporary, `${JSON.stringify(receipt)}\n`, { mode: 0o600, flag: "wx" });
        await rename(temporary, path);
      } finally {
        await rm(temporary, { force: true });
      }
    });
  };

  onClose = (): Promise<void> => {
    const openedAt = this.openedAt;
    this.openedAt = undefined;
    this.lastRead = undefined;
    if (openedAt === undefined) return this.pending;
    this.enqueue(async (_directory, path) => {
      let current;
      try { current = JSON.parse(await readFile(path, "utf8")); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
      // Another process may have opened a replacement stream. Never erase its proof.
      if (current.pid === process.pid && current.opened_at === new Date(openedAt).toISOString()) {
        await rm(path, { force: true });
      }
    });
    return this.pending;
  };

  flush(): Promise<void> { return this.pending; }

  private enqueue(action: (directory: string, path: string) => Promise<void>): void {
    this.pending = this.pending.then(async () => {
      const directory = join(this.options.identityHome, "receive");
      await mkdir(directory, { recursive: true, mode: 0o700 });
      if (!(await lstat(directory)).isDirectory()) throw new Error("receive directory must not be a symlink");
      // Serialize rename and owner-checked deletion across adapter processes.
      const release = await lock(directory, { realpath: false, retries: { retries: 5, minTimeout: 10, maxTimeout: 100 } });
      try { await action(directory, join(directory, "stream.json")); }
      finally { await release(); }
    }).catch((error) => {
      if (this.reportedError) return;
      this.reportedError = true;
      this.options.onError?.(`aweb receive receipt unavailable: ${error instanceof Error ? error.message : String(error)}`);
    });
  }
}
