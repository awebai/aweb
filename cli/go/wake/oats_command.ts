import { spawn } from "node:child_process";

export interface OATSEnvelope {
  ok?: boolean;
  result?: { home?: string; backend?: string; present?: boolean; state?: string; submitted?: boolean };
  error?: { code?: string; message?: string };
}


// Await close even on timeout/abort: callers must not accumulate live commands
// or open pipes while delivery retries.
export function runOATS(bin: string, args: string[], input = "", options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<OATSEnvelope> {
  return new Promise((resolve, reject) => {
    const signal = options.signal;
    if (signal?.aborted) { reject(new Error("oats command aborted")); return; }
    const hasInput = input.length > 0;
    const child = spawn(bin, args, { stdio: [hasInput ? "pipe" : "ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let failure: Error | undefined;
    const stop = (error: Error) => {
      failure ??= error;
      child.kill("SIGKILL");
      // Descendants may inherit pipes. Close our ends so they cannot extend
      // this command deadline; the supervisor owns final process-group cleanup.
      child.stdin?.destroy();
      child.stdout?.destroy();
      child.stderr?.destroy();
    };
    const timeoutMs = options.timeoutMs ?? 30_000;
    const timer = setTimeout(() => stop(new Error(`oats command timed out after ${timeoutMs}ms`)), timeoutMs);
    const onAbort = () => stop(new Error("oats command aborted"));
    signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout!.setEncoding("utf8");
    child.stderr!.setEncoding("utf8");
    child.stdout!.on("data", (chunk) => { stdout += chunk; });
    child.stderr!.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => { failure ??= error; });
    child.on("close", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      if (failure) { reject(failure); return; }
      try {
        const envelope = JSON.parse(stdout.trim()) as OATSEnvelope;
        if (!envelope.ok) throw new Error(`${envelope.error?.code || "E_OATS"}: ${envelope.error?.message || "oats command failed"}`);
        resolve(envelope);
      } catch (error) {
        reject(new Error((stderr || (error instanceof Error ? error.message : String(error))).trim()));
      }
    });
    if (hasInput && child.stdin) {
      child.stdin.on("error", stop);
      child.stdin.end(input);
    }
  });
}
