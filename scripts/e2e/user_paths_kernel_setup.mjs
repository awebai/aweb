import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

export const DiagnosticOutput = Object.freeze({ Public: "public", Credential: "credential" });

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
