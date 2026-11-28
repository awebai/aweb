import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync, writeFileSync, symlinkSync, readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { setTimeout as sleep } from "node:timers/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import { DiagnosticOutput, cleanupPassiveTerminal, createProbeAssertions, wakeTimestampIsUnset, kernelSessionSnapshot, preparePassiveKernelLaunch, runKernelLifecycleCommand, runKernelProbeCommand } from "./user_paths_kernel_setup.mjs";

const CleanupCase = Object.freeze({ NoServer: "no-server", ExitFailure: "exit-failure", SpawnError: "spawn-error", Signal: "signal" });

test("passive terminal cleanup retains its socket root on child failure", () => {
  for (const outcome of Object.values(CleanupCase)) {
    const root = mkdtempSync("/tmp/kpc-");
    try {
      const env = { HOME: root, TMUX_TMPDIR: root, PATH: process.env.PATH };
      let tmuxBinary;
      if (outcome === CleanupCase.NoServer) tmuxBinary = spawnSync("/usr/bin/which", ["tmux"], { encoding: "utf8" }).stdout.trim();
      else if (outcome === CleanupCase.ExitFailure) tmuxBinary = "/usr/bin/false";
      else if (outcome === CleanupCase.SpawnError) tmuxBinary = join(root, "missing-executable");
      else {
        tmuxBinary = join(root, "signalled-child.mjs");
        writeFileSync(tmuxBinary, `#!${process.execPath}\nprocess.kill(process.pid, "SIGTERM");\n`, { mode: 0o700 });
      }
      if (outcome === CleanupCase.NoServer) {
        cleanupPassiveTerminal({ root, tmuxBinary, env });
        assert.equal(existsSync(root), false, "confirmed no-server cleanup removes its root");
      } else {
        assert.throws(() => cleanupPassiveTerminal({ root, tmuxBinary, env }), /Owned tmux cleanup failed.*socket root retained/, outcome);
        assert.equal(existsSync(root), true, `${outcome} preserves the socket root for inspection`);
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test("passive terminal cleanup waits for the panes the stopped server leaves running", async () => {
  // kill-server returns before the panes exit. A pane's shell that writes its
  // history as it exits must not race the root's removal.
  const scratch = mkdtempSync("/tmp/kpw-");
  const root = join(scratch, "root"), marker = join(scratch, "pane-last-write"), ready = join(scratch, "pane-ready"), pidFile = join(scratch, "pane-pid");
  mkdirSync(root);
  // The pane is not the test's child, as a real pane is the server's: a
  // supervisor, the test's own child, starts it and waits for it, so its pid
  // stays the pane's until the supervisor reaps it. The pane says it is ready
  // only once its SIGHUP handler is installed, so the signal cannot arrive
  // first. On failure the test stops the supervisor, which ends its pane
  // through the child handle; a reaped pane is never signalled.
  const paneScript = `process.on("SIGHUP", () => setTimeout(() => { require("fs").writeFileSync(${JSON.stringify(marker)}, "history"); process.exit(0); }, 300));require("fs").writeFileSync(${JSON.stringify(ready)}, "");setInterval(() => {}, 1000)`;
  const supervisor = spawn(process.execPath, ["-e", `
const { spawn } = require("node:child_process");
const pane = spawn(process.execPath, ["-e", ${JSON.stringify(paneScript)}], { stdio: "ignore" });
require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(pane.pid));
pane.on("exit", () => process.exit(0));
process.on("SIGTERM", () => pane.kill("SIGKILL"));
`], { stdio: "ignore" });
  const supervised = once(supervisor, "exit");
  try {
    const readyBy = Date.now() + 10000;
    while (!(existsSync(ready) && existsSync(pidFile)) && Date.now() < readyBy) await sleep(20);
    assert.equal(existsSync(ready), true, "the pane installed its SIGHUP handler");
    const pid = Number(readFileSync(pidFile, "utf8").trim());
    assert.ok(Number.isInteger(pid) && pid > 0, "the pane started");
    const tmuxBinary = join(scratch, "tmux.mjs");
    writeFileSync(tmuxBinary, `#!${process.execPath}
const args = process.argv.slice(2).join(" ");
if (args.includes("list-panes")) { process.stdout.write("${pid}\\n"); process.exit(0); }
if (args.includes("kill-server")) { process.kill(${pid}, "SIGHUP"); process.exit(0); }
process.exit(1);
`, { mode: 0o700 });
    cleanupPassiveTerminal({ root, tmuxBinary, env: { PATH: process.env.PATH } });
    assert.equal(existsSync(marker), true, "cleanup returns only after the pane's last write");
    assert.equal(existsSync(root), false, "the root is removed after the pane exits");
    // The pane exited on its own: its supervisor reaps it and ends.
    const [code] = await Promise.race([supervised, sleep(10000).then(() => ["timeout"])]);
    assert.equal(code, 0, "the supervisor saw its pane exit");
  } finally {
    if (supervisor.exitCode === null && supervisor.signalCode === null) {
      supervisor.kill("SIGTERM");
      await supervised;
    }
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("passive terminal cleanup counts an unreaped pane as exited", () => {
  // Where nothing reaps orphans (a container whose PID 1 is not an init), a
  // pane that has exited stays a zombie, which signal 0 still reaches.
  const root = mkdtempSync("/tmp/kpz-");
  const parentFile = join(root, "parent"), paneFile = join(root, "pane");
  try {
    spawnSync("/bin/sh", ["-c", `(sh -c '${JSON.stringify(process.execPath)} -e "setTimeout(() => process.exit(0), 100)" & echo $! > ${paneFile}; echo $$ > ${parentFile}; exec sleep 60') >/dev/null 2>&1 &`]);
    const deadline = Date.now() + 10000;
    while (!(existsSync(paneFile) && existsSync(parentFile)) && Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    const pid = Number(readFileSync(paneFile, "utf8").trim());
    // Wait for the pane to become the zombie this test is about, not for a
    // time it usually takes to get there.
    const state = () => spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim();
    const zombieBy = Date.now() + 10000;
    while (!state().startsWith("Z") && Date.now() < zombieBy) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    assert.ok(state().startsWith("Z"), `the exited pane is a zombie (state ${JSON.stringify(state())})`);
    assert.doesNotThrow(() => process.kill(pid, 0), "the exited pane is still a process: a zombie");
    const tmuxBinary = join(root, "tmux.mjs");
    writeFileSync(tmuxBinary, `#!${process.execPath}
const args = process.argv.slice(2).join(" ");
if (args.includes("list-panes")) { process.stdout.write("${pid}\\n"); process.exit(0); }
process.exit(args.includes("kill-server") ? 0 : 1);
`, { mode: 0o700 });
    const started = Date.now();
    cleanupPassiveTerminal({ root, tmuxBinary, env: { PATH: process.env.PATH } });
    assert.ok(Date.now() - started < 5000, "cleanup did not wait for an exited pane");
    assert.equal(existsSync(root), false, "the root is removed");
  } finally {
    const parent = existsSync(parentFile) ? Number(readFileSync(parentFile, "utf8").trim()) : 0;
    if (parent > 0) { try { process.kill(parent, "SIGKILL"); } catch {} }
    rmSync(root, { recursive: true, force: true });
  }
});

test("the wake probe keeps its socket root when its owned tmux cleanup fails", () => {
  // The real probe, failing early, tears down through its own finally block.
  const gateStaged = "/opt/user-paths/released-oats";
  const staged = existsSync(gateStaged) ? gateStaged : fileURLToPath(new URL("../../candidate-gate/released-oats", import.meta.url));
  assert.ok(existsSync(join(staged, "node_modules/@awebai/oats/bin/oats.mjs")), "Run make prepare-released-kernel-test first.");
  const probe = fileURLToPath(new URL("./user_paths_oats.mjs", import.meta.url));
  const tmuxBinary = spawnSync("/usr/bin/which", ["tmux"], { encoding: "utf8" }).stdout.trim();
  assert.ok(tmuxBinary, "the no-server case requires installed tmux");
  for (const outcome of [CleanupCase.NoServer, CleanupCase.ExitFailure, CleanupCase.Signal]) {
    const scratch = mkdtempSync("/tmp/kwp-");
    try {
      const root = join(scratch, "root"), output = join(scratch, "receipt.json"), notAw = join(scratch, "not-aw");
      // The probe's PATH starts with <root>/bin, which its directory setup keeps.
      mkdirSync(join(root, "bin"), { recursive: true, mode: 0o700 });
      if (outcome === CleanupCase.NoServer) symlinkSync(tmuxBinary, join(root, "bin/tmux"));
      else if (outcome === CleanupCase.ExitFailure) writeFileSync(join(root, "bin/tmux"), "#!/bin/sh\nexit 1\n", { mode: 0o700 });
      else writeFileSync(join(root, "bin/tmux"), "#!/bin/sh\nkill -TERM $$\n", { mode: 0o700 });
      // Not an executable aw: the probe fails at its first aw command.
      writeFileSync(notAw, "not an aw binary\n", { mode: 0o600 });
      const run = spawnSync(process.execPath, [probe, "--aw", notAw, "--root", root, "--seat", scratch, "--fixture-home", scratch, "--sender", scratch,
        "--team", "members:probe.test", "--source-commit", "0000000", "--released-artifacts", staged, "--output", output], { encoding: "utf8", timeout: 60000 });
      assert.equal(run.status, 1, `${outcome}: the probe fails`);
      const receipt = JSON.parse(readFileSync(output, "utf8"));
      assert.equal(receipt.result, "FAILED", outcome);
      if (outcome === CleanupCase.NoServer) {
        assert.deepEqual(receipt.cleanup_errors, [], "confirmed no-server cleanup records no error");
        assert.equal(existsSync(root), false, "confirmed no-server cleanup removes the probe root");
      } else {
        assert.match(receipt.cleanup_errors.join("\n"), /Owned tmux cleanup failed.*socket root retained/, outcome);
        assert.equal(existsSync(join(root, "tmux")), true, `${outcome} preserves the socket root for inspection`);
      }
    } finally { rmSync(scratch, { recursive: true, force: true }); }
  }
});

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
      cleanupPassiveTerminal({ root, tmuxBinary, env });
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


test("quiet startup accepts Go zero time and refuses recorded or malformed input", () => {
  // Actual ChannelCoreStatus JSON and the a071 prelaunch receipt use this zero.
  const wire = JSON.parse('{"last_input_at":"0001-01-01T00:00:00Z"}');
  for (const value of [undefined, "", wire.last_input_at]) assert.equal(wakeTimestampIsUnset(value), true);
  for (const value of ["2026-11-20T05:23:24.123Z", "invalid", null, false, 0]) assert.equal(wakeTimestampIsUnset(value), false);
  const root = mkdtempSync(join(tmpdir(), "kernel-assertion-receipt-"));
  try {
    const output = join(root, "receipt.json");
    const evidence = { wake_fresh: { last_input_at: "2026-11-20T05:23:24.123Z" } };
    const probe = createProbeAssertions({ evidence, output });
    assert.throws(() => probe.ok(wakeTimestampIsUnset(evidence.wake_fresh.last_input_at), "startup inspection submits no input"), /Inspect the recorded assertion values/);
    const saved = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(saved.wake_fresh.last_input_at, evidence.wake_fresh.last_input_at);
    assert.equal(saved.assertions["startup inspection submits no input"].actual, false);
    assert.equal(saved.failed_check, "startup inspection submits no input");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("probe checks persist before verification and withhold private values", () => {
  const root = mkdtempSync(join(tmpdir(), "kernel-assertion-privacy-"));
  try {
    const output = join(root, "receipt.json"), evidence = {};
    const probe = createProbeAssertions({ evidence, output });
    // deepEqual invokes this getter while verifying, after persistence.
    probe.deepEqual({ get type() { return JSON.parse(readFileSync(output, "utf8")).assertions["before verification"].actual.type; } }, { type: "object" }, "before verification");
    probe.equal("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "public timestamp");
    probe.match("public", /^public$/, "public match");
    probe.ok("fixture-credential-marker", "opaque truthy input");
    for (const [method, actual, expected] of [
      ["equal", "fixture-credential-marker", "other"],
      ["deepEqual", { Authorization: "fixture-credential-marker" }, {}],
      ["match", "fixture-credential-marker", /^public$/],
    ]) {
      assert.throws(() => probe[method](actual, expected, `private ${method}`), (error) => {
        assert.doesNotMatch(error.message, /fixture-credential-marker/);
        assert.ok(error.cause);
        return true;
      });
    }
    const saved = readFileSync(output, "utf8");
    assert.doesNotMatch(saved, /fixture-credential-marker|Authorization/);
    assert.equal(JSON.parse(saved).assertions["public timestamp"].actual, "0001-01-01T00:00:00Z");
    assert.equal(JSON.parse(saved).assertions["opaque truthy input"].actual.withheld, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
