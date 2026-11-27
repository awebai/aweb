import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import strictAssert from "node:assert/strict";

export const DiagnosticOutput = Object.freeze({ Public: "public", Credential: "credential" });

const GO_ZERO_TIME = "0001-01-01T00:00:00Z";
const PUBLIC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const PUBLIC_CHECK_TEXT = new Set(["PASSED", "FAILED", "pending", "active", "not-launched", "700", "600"]);

export function wakeTimestampIsUnset(value) {
  // ChannelCoreStatus uses time.Time: its zero is a nonempty JSON string.
  return value === undefined || value === "" || value === GO_ZERO_TIME;
}

function publicAssertionValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string" && (PUBLIC_TIMESTAMP.test(value) || /^[0-7]{3,4}$/.test(value) || PUBLIC_CHECK_TEXT.has(value))) return value;
  if (Array.isArray(value)) return value.map(publicAssertionValue);
  // No arbitrary string/object/message fallback: tokens can reach assert.ok.
  return { type: typeof value, withheld: true };
}

export function createProbeAssertions({ evidence, output }) {
  evidence.assertions = {};
  const persist = () => {
    if (!output) return; // Missing --output has no destination for a receipt.
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600 });
  };
  const check = ({ method, actual, expected, label, verify }) => {
    // Labels come from fixed probe checks; unrecognized values stay withheld.
    evidence.assertions[label] = { method, actual: publicAssertionValue(actual), expected: publicAssertionValue(expected) };
    persist();
    try { verify(); }
    catch (error) {
      evidence.failed_check ??= label;
      persist();
      throw new Error(`Probe check failed: ${label}. Inspect the recorded assertion values before retrying.`, { cause: error });
    }
  };
  return {
    ok(actual, label) { check({ method: "ok", actual, expected: true, label, verify: () => strictAssert.ok(actual, label) }); },
    equal(actual, expected, label) { check({ method: "equal", actual, expected, label, verify: () => strictAssert.equal(actual, expected, label) }); },
    deepEqual(actual, expected, label) { check({ method: "deepEqual", actual, expected, label, verify: () => strictAssert.deepEqual(actual, expected, label) }); },
    match(actual, expected, label) { check({ method: "match", actual, expected, label, verify: () => strictAssert.match(actual, expected, label) }); },
  };
}

export function runKernelLifecycleCommand({ kernel, args, cwd, env, timeout = 60000 }) {
  return runKernelProbeCommand({
    name: `oats ${args.slice(0, 2).join(" ")}`,
    argv: [process.execPath, kernel, ...args], cwd, env, timeout,
    output: DiagnosticOutput.Credential,
  });
}

export function preparePassiveKernelLaunch({ bin, node }) {
  const program = join(bin, "passive-session.mjs");
  // Execute the Node program itself: the kernel's Codex flags must become
  // script argv, never options to the Node interpreter. This is an explicitly
  // configured passive terminal, with no Codex binary or model claim.
  writeFileSync(program, `#!${node}\nprocess.stdout.write("R26 passive terminal ready\\n");\nsetInterval(() => {}, 1000);\n`, { mode: 0o700 });
  return { harness: "codex", executable: program };
}

export function kernelSessionSnapshot(answer) {
  const boolean = (value) => typeof value === "boolean" ? value : null;
  const state = answer?.result?.state;
  return {
    ok: boolean(answer?.ok),
    present: boolean(answer?.result?.present),
    running: boolean(answer?.result?.running),
    state: ["not-launched", "stopped", "shell", "unknown"].includes(state) ? state : null,
  };
}

function diagnosticTail(output, policy) {
  if (policy === DiagnosticOutput.Credential) return "<credential output withheld>";
  // Public output is reserved for known non-secret producers, not lifecycle JSON.
  return String(output ?? "").slice(-4096);
}

export function runKernelProbeCommand({ name, argv, cwd, env, timeout = 60000, output = DiagnosticOutput.Credential }) {
  if (!Object.values(DiagnosticOutput).includes(output)) throw new Error("Unknown probe diagnostic output policy");
  const started = performance.now();
  const result = spawnSync(argv[0], argv.slice(1), { cwd, env, encoding: "utf8", timeout });
  if (result.error || result.status !== 0) {
    const diagnostic = {
      command: name, executable: argv[0], pid: result.pid,
      elapsed_ms: Math.round(performance.now() - started), timeout_ms: timeout,
      status: result.status, signal: result.signal,
      error_code: result.error?.code ?? kernelCommandErrorCode(result.stdout),
      stdout_tail: diagnosticTail(result.stdout, output), stderr_tail: diagnosticTail(result.stderr, output),
    };
    const error = new Error(`${JSON.stringify(diagnostic)}. Inspect this child's diagnostics before rerunning the user-paths stage.`, { cause: result.error });
    error.diagnostic = diagnostic;
    throw error;
  }
  return result.stdout;
}

const PANE_EXIT_MS = 10000;

// A zombie has exited: where nothing reaps orphans (a container whose PID 1 is
// not an init), an exited pane stays one, and signal 0 still reaches it.
function processRunning(pid) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    return error.code !== "ESRCH";
  }
  let state;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    state = stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3);
  } catch {
    state = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout?.trim().charAt(0);
  }
  return state !== "Z";
}

// Stops the owned tmux server, waits for its panes to exit, then removes root.
// kill-server returns before the panes exit, and a pane's shell can still
// write (its history, under HOME) as it does. A failed, signalled or timed-out
// stop, or a pane still running after the bound, keeps root, which holds the
// server's socket, for inspection.
export function cleanupPassiveTerminal({ root, tmuxBinary, env }) {
  const listed = spawnSync(tmuxBinary, ["-L", "oats", "list-panes", "-a", "-F", "#{pane_pid}"], { env, encoding: "utf8", timeout: 10000 });
  const panes = listed.status === 0 ? listed.stdout.split(/\s+/).filter((field) => /^[1-9][0-9]*$/.test(field)).map(Number) : [];
  const stopped = spawnSync(tmuxBinary, ["-L", "oats", "kill-server"], { env, encoding: "utf8", timeout: 10000 });
  const noServer = stopped.status === 1 && /^(?:no server running on [^\r\n]+|error connecting to [^\r\n]+ \(No such file or directory\))\s*$/.test(stopped.stderr);
  if (stopped.error || stopped.signal || (stopped.status !== 0 && !noServer)) {
    throw new Error(`Owned tmux cleanup failed (status=${stopped.status}, signal=${stopped.signal}, code=${stopped.error?.code ?? "none"}); socket root retained at ${root}. Inspect the owned server before removing that directory.`, { cause: stopped.error });
  }
  const deadline = performance.now() + PANE_EXIT_MS;
  let running = panes.filter(processRunning);
  while (running.length && performance.now() < deadline) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    running = running.filter(processRunning);
  }
  if (running.length) {
    throw new Error(`Owned tmux cleanup failed: panes ${running.join(", ")} still running ${PANE_EXIT_MS} ms after kill-server; socket root retained at ${root}. Inspect them before removing that directory.`);
  }
  rmSync(root, { recursive: true, force: true });
}

export function prepareKernelProbeDirectories({ root }) {
  const home = join(root, "home"), deployment = join(root, "deploy");
  const source = join(root, "source"), bin = join(root, "bin");
  // Released OATS discovers a deployment through agents/ (docs/wake-runner-integrity.md).
  for (const path of [home, deployment, join(deployment, "agents"), source, bin, join(root, "tmux")]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return { home, deployment, source, bin };
}

export function kernelCommandErrorCode(output) {
  // Command stdout can contain private results; retain only the kernel's code.
  try {
    const code = JSON.parse(output)?.error?.code;
    return typeof code === "string" && /^E_[A-Z0-9_]{1,61}$/.test(code) ? code : null;
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    return null;
  }
}
