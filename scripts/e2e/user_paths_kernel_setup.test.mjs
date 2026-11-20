import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync, writeFileSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import { DiagnosticOutput, kernelSessionSnapshot, preparePassiveKernelLaunch, runKernelLifecycleCommand, runKernelProbeCommand } from "./user_paths_kernel_setup.mjs";

test("released kernel starts, inspects and retires the actual passive terminal", () => {
  const root = mkdtempSync("/tmp/kpr-");
  const home = join(root, "home"), deployment = join(root, "deploy"), source = join(root, "source"), bin = join(root, "bin"), tmux = join(root, "tmux");
  for (const directory of [home, deployment, join(deployment, "agents"), source, bin, tmux]) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const staged = "/opt/user-paths/released-oats/node_modules/@awebai/oats/bin/oats.mjs";
  const kernel = existsSync(staged) ? staged : fileURLToPath(new URL("../../candidate-gate/released-oats/node_modules/@awebai/oats/bin/oats.mjs", import.meta.url));
  // Both tools are real installed programs; the owned PATH excludes harnesses.
  const tmuxBinary = spawnSync("/usr/bin/which", ["tmux"], { encoding: "utf8" }).stdout.trim();
  assert.ok(tmuxBinary, "the released terminal lifecycle control requires installed tmux");
  symlinkSync(tmuxBinary, join(bin, "tmux"));
  const env = { HOME: home, PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin`, TMUX_TMPDIR: tmux, OATS_TMUX_SESSION: "passive-control", OATS_REMOTE_CACHE: join(root, "cache"), GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
  const launch = preparePassiveKernelLaunch({ bin, node: process.execPath });
  let instance;
  const oats = (...args) => JSON.parse(runKernelLifecycleCommand({ kernel, args, cwd: deployment, env }));
  try {
    const ref = pathToFileURL(source).href;
    writeFileSync(join(source, "oats-workspace.yaml"), `schemaVersion: 2\nname: passive-control\nmembers: [${ref}]\nlocalTeams: true\n`);
    writeFileSync(join(source, "oats-membership.yaml"), `schemaVersion: 2\nworkspace: ${ref}\n`);
    const soul = join(source, "souls/probe");
    mkdirSync(soul, { recursive: true });
    writeFileSync(join(soul, "soul.yaml"), `schemaVersion: 2\nname: probe\ndescription: passive terminal control\nwork: directory\nlaunch: { harness: ${launch.harness} }\n`);
    writeFileSync(join(soul, "AGENTS.md"), "Disposable passive terminal control.\n");
    for (const args of [["init", "-q"], ["add", "."], ["commit", "-qm", "passive control"]]) {
      const result = spawnSync("git", ["-C", source, "-c", "user.name=Wake probe", "-c", "user.email=probe@example.invalid", ...args], { env, encoding: "utf8" });
      assert.equal(result.status, 0, `fixture git ${args[0]} completes`);
    }
    writeFileSync(join(deployment, "oats-local.yaml"), `schemaVersion: 2\nworkspace: ${ref}\nlaunch-configs:\n  passive: ${JSON.stringify(launch)}\nsouls:\n  launch:\n    '*': passive\n`);
    const spawned = oats("spawn", "probe", "--name", "passive-control", "--backend", "tmux", "--no-launch", "--json");
    assert.equal(spawned.ok, true, "passive spawn succeeds");
    instance = spawned.result.instance;
    const targetHome = spawned.result.home;
    assert.equal(oats("session", "inspect", "--home", targetHome, "--json").result.state, "not-launched", "the terminal starts with no process");
    assert.equal(oats("session", "start", "--home", targetHome, "--json").ok, true, "session start confirms its launch");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
    const observed = oats("session", "inspect", "--home", targetHome, "--json").result;
    // Capture only this control's own generated launch output for causal evidence.
    const pane = spawnSync(tmuxBinary, ["-L", "oats", "capture-pane", "-p", "-S", "-100", "-t", "=passive-control:=passive-control"], { env, encoding: "utf8" });
    assert.equal(observed.present, true, `started terminal present; state=${observed.state}; fixture pane=${pane.stdout.trim()}`);
    assert.equal(observed.running, true, `started terminal running; state=${observed.state}; fixture pane=${pane.stdout.trim()}; capture error=${pane.stderr}`);
    assert.match(pane.stdout, /R26 passive terminal ready/, "the actual idle program ran, not just the kernel launch recorder");
    const retired = oats("retire", instance, "--json");
    assert.equal(retired.retired, instance, "released retirement names this instance directly, without an ok envelope");
    assert.equal(retired.removedDir, true, "released retirement removes this owned home");
    assert.equal(existsSync(targetHome), false, "retired home is absent");
    instance = undefined;
  } finally {
    try { if (instance) oats("retire", instance, "--json"); }
    finally {
      spawnSync(tmuxBinary, ["-L", "oats", "kill-server"], { env, encoding: "utf8", timeout: 10000 });
      rmSync(root, { recursive: true, force: true });
    }
  }
});

for (const [name, payload] of [
  ["Authorization", JSON.stringify({ headers: { Authorization: "Bearer fixture-credential-marker" } })],
  ["error message", JSON.stringify({ error: { code: "E_PROVIDER_FAILED", message: "private fixture-credential-marker" } })],
  ["non-JSON", "private fixture-credential-marker"],
  ["token", JSON.stringify({ token: "fixture-credential-marker" })],
]) {
  test(`lifecycle ${name} failure withholds credentials from both retained fields`, () => {
    const root = mkdtempSync(join(tmpdir(), "kernel-private-diagnostic-"));
    try {
      const child = join(root, "child.mjs");
      writeFileSync(child, `process.stdout.write(${JSON.stringify(payload)});process.stderr.write(${JSON.stringify(payload)});process.exit(7);\n`);
      assert.throws(() => runKernelLifecycleCommand({ kernel: child, args: ["spawn", "probe"], cwd: root, env: process.env }), (error) => {
        assert.equal(error.diagnostic.command, "oats spawn probe");
        assert.equal(error.diagnostic.status, 7);
        if (name === "error message") assert.equal(error.diagnostic.error_code, "E_PROVIDER_FAILED");
        assert.doesNotMatch(error.message, /fixture-credential-marker/);
        assert.doesNotMatch(JSON.stringify(error.diagnostic), /fixture-credential-marker/);
        return true;
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("timeout identifies the actual child and retains bounded public tails", () => {
  const command = {
    name: "owned kernel timeout control", cwd: process.cwd(), env: process.env,
    argv: [process.execPath, "-e", "console.log(JSON.stringify({phase:'preflight'}));console.error('public stderr marker');setInterval(()=>{},1000)"],
    timeout: 500, output: DiagnosticOutput.Public,
  };
  assert.throws(() => runKernelProbeCommand(command), (error) => {
    assert.equal(error.cause.code, "ETIMEDOUT");
    const detail = error.diagnostic;
    assert.equal(detail.command, command.name);
    assert.equal(detail.executable, process.execPath);
    assert.ok(Number.isInteger(detail.pid));
    assert.equal(detail.timeout_ms, 500);
    assert.ok(detail.elapsed_ms >= 500);
    assert.ok(detail.elapsed_ms < 10000);
    assert.equal(JSON.parse(detail.stdout_tail).phase, "preflight");
    assert.match(detail.stderr_tail, /public stderr marker/);
    assert.match(error.message, /Inspect this child's diagnostics before rerunning/);
    return true;
  });
});

test("credential failures withhold both streams and normal success preserves output", () => {
  const request = {
    name: "owned credential control", cwd: process.cwd(), env: process.env,
    argv: [process.execPath, "-e", "console.log('private-stdout');console.error('private-stderr');process.exit(7)"],
  };
  assert.throws(() => runKernelProbeCommand(request), (error) => {
    assert.equal(error.diagnostic.status, 7);
    assert.doesNotMatch(error.message, /private-stdout|private-stderr/);
    assert.equal(error.diagnostic.stdout_tail, "<credential output withheld>");
    assert.equal(error.diagnostic.stderr_tail, "<credential output withheld>");
    return true;
  });
  assert.equal(runKernelProbeCommand({ ...request, argv: [process.execPath, "-e", "process.stdout.write('complete')"] }), "complete");
});

test("released kernel plans the passive terminal without a Claude plugin probe", async () => {
  const root = mkdtempSync(join(tmpdir(), "kernel-passive-plan-"));
  try {
    const home = join(root, "home"), bin = join(root, "bin");
    mkdirSync(home, { mode: 0o700 });
    mkdirSync(bin, { mode: 0o700 });
    const launch = preparePassiveKernelLaunch({ bin, node: process.execPath });
    const staged = "/opt/user-paths/released-oats/node_modules/@awebai/oats/lib/core.mjs";
    const local = new URL("../../candidate-gate/released-oats/node_modules/@awebai/oats/lib/core.mjs", import.meta.url);
    const { planLaunch } = await import(existsSync(staged) ? pathToFileURL(staged) : local);
    // The released provider's session-mode requirement. The real kernel owns
    // applicability and package discovery; this is a preflight, not a provider run.
    const provider = {
      id: "oats.aweb", settings: { delivery: "session" },
      manifest: { requires: [{ runtime: "claude", package: "aweb-channel@awebai-marketplace", when: { delivery: "session" }, ifInstalled: true, minVersion: "1.7.9" }] },
    };
    const plan = planLaunch({
      home, instance: "passive-probe", contextDir: root,
      launchConfigs: { passive: { ...launch, name: "passive" } },
      selection: { launchConfig: "passive" }, resolvedCfg: { capabilities: [provider] },
      env: { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
    });
    assert.equal(plan.harness, "codex");
    assert.equal(plan.recipe.executable, launch.executable);
    assert.ok(plan.command.includes(launch.executable));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("session evidence retains false fields and withholds unrecognized lifecycle data", () => {
  const answer = { ok: true, result: { present: false, running: false, state: "stopped", Authorization: "fixture-credential-marker", message: "fixture-credential-marker" } };
  assert.deepEqual(kernelSessionSnapshot(answer), { ok: true, present: false, running: false, state: "stopped" });
  assert.deepEqual(kernelSessionSnapshot({ ok: "fixture-credential-marker", result: { state: "fixture-credential-marker" } }), { ok: null, present: null, running: null, state: null });
});
