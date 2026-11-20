import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { DiagnosticOutput, preparePassiveKernelLaunch, runKernelLifecycleCommand, runKernelProbeCommand } from "./user_paths_kernel_setup.mjs";

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

test("released kernel plans the passive session without a Claude plugin probe", async () => {
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
    assert.equal(plan.recipe.executable, process.execPath);
    assert.ok(plan.command.includes(launch.args[0]));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
