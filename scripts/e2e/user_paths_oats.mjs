// Released OATS kernel -> candidate aw wake seam. The fixture construction uses
// oats-aweb v1.42.1 test/resident-journey.test.mjs's real local-member workspace.
// A supported passive launch executable avoids a model call, per OATS's launch
// configuration contract. Neither the kernel, provider, aw nor broker is faked.
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, mkdirSync, readFileSync, statSync, existsSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { DiagnosticOutput, cleanupPassiveTerminal, createProbeAssertions, wakeTimestampIsUnset, kernelSessionSnapshot, prepareKernelProbeDirectories, preparePassiveKernelLaunch, runKernelLifecycleCommand, runKernelProbeCommand } from "./user_paths_kernel_setup.mjs";

const KernelBackend = Object.freeze({ Tmux: "tmux" });
const OWNED_TMUX = ["tmux", "-L", "oats"];
const ProbeOutcome = Object.freeze({ Passed: "PASSED", Failed: "FAILED" });
const { values } = parseArgs({ options: {
  aw: { type: "string" }, root: { type: "string" }, seat: { type: "string" },
  "fixture-home": { type: "string" }, sender: { type: "string" }, team: { type: "string" }, output: { type: "string" },
  "source-commit": { type: "string" },
  "released-lifecycle": { type: "boolean" }, "released-artifacts": { type: "string" }, "aw-actor": { type: "string" },
} });
const released = values["released-lifecycle"];
const manual = Boolean(values["aw-actor"]);
if (released && !values["released-artifacts"]) {
  throw new Error("--released-artifacts is required for published client validation");
}
const STAGED = values["released-artifacts"] || "/opt/user-paths/released-oats";
const KERNEL = join(STAGED, "node_modules/@awebai/oats/bin/oats.mjs");
const artifacts = released ? JSON.parse(readFileSync(join(STAGED, "provenance.json"), "utf8")) : null;
const PIN = artifacts?.provider ?? JSON.parse(readFileSync(join(STAGED, "provider.json"), "utf8"));
const PROVIDER = join(released ? STAGED : "/opt/user-paths/oats-aweb", PIN.capability_path);

const evidence = {};
const assert = createProbeAssertions({ evidence, output: values.output });
for (const option of ["aw", "root", "seat", "sender", "team", "output", "source-commit", "fixture-home"]) {
  assert.ok(values[option], `--${option} is required`);
}
const root = resolve(values.root);
const { home, deployment, source, bin } = prepareKernelProbeDirectories({ root });
Object.assign(evidence, { scope: "released OATS kernel -> candidate aw wake path; not the lab image, supervisor or Helm storage", provider: PIN, candidate_source_commit: values["source-commit"], candidate_binary_sha256: createHash("sha256").update(readFileSync(values.aw)).digest("hex"), process_uid: process.geteuid(), process_gid: process.getegid() });
if (released) {
  evidence.scope = manual ? "released aw manual native-broker registration" : "released OATS kernel and aweb provider with released aw";
  evidence.lifecycle = {};
}
function recordLifecycle(operation, visible) {
  if (manual && operation === "wake") evidence.lifecycle["aw/wake"] = { status: "PASSED", visible };
  if (released && !manual) evidence.lifecycle["oats/" + operation] = { status: "PASSED", visible };
}
const env = {
  PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin`, HOME: home,
  TMUX_TMPDIR: join(root, "tmux"), OATS_TMUX_SESSION: "r20-kernel-wake",
  OATS_CLI_BIN: KERNEL, OATS_REMOTE_CACHE: join(root, "cache"),
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
  AW_NO_UPDATE_CHECK: "1", NO_COLOR: "1", APP_ENV: "development",
  AWEB_FEDERATION_TEST: "1", AWID_REGISTRY_URL: "http://awid:8010", AWEB_URL: "http://server:8000",
};
symlinkSync(resolve(values.aw), join(bin, "aw"));
writeFileSync(join(bin, "oats"), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(KERNEL)} "$@"\n`, { mode: 0o700 });
const passiveLaunch = preparePassiveKernelLaunch({ bin, node: process.execPath });
function command({ name, argv, cwd = deployment, timeout = 60000, output = DiagnosticOutput.Credential }) {
  return runKernelProbeCommand({ name, argv, cwd, env, timeout, output });
}
const oats = (...args) => runKernelLifecycleCommand({ kernel: KERNEL, args, cwd: deployment, env });
const aw = ({ identity, args }) => command({ name: `aw ${args.slice(0, 3).join(" ")}`, argv: [join(bin, "aw"), "--identity-home", join(identity, ".aw"), ...args], cwd: identity });
const parseObject = (raw) => { const value = JSON.parse(raw); assert.ok(value && typeof value === "object" && !Array.isArray(value), "expected command JSON object"); return value; };
function wakeInstances(status) {
  const rows = status.instances ?? [];
  assert.ok(Array.isArray(rows), "wake instances must be an array");
  return rows;
}
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
async function until({ read, ready, label }) {
  const deadline = Date.now() + 20000;
  let value;
  do { value = read(); if (ready(value)) return value; await sleep(100); } while (Date.now() < deadline);
  throw new Error(`${label} did not become ready: ${JSON.stringify(value)}`);
}
async function stopOwnedBroker(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((done) => child.once("exit", done));
  child.kill("SIGTERM");
  await Promise.race([exited, sleep(8000)]);
  if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await exited; }
}
function executionPermissions(status) {
  const executable = wakeInstances(status).find((row) => row.home === instanceHome)?.channel_core?.bundle_path;
  assert.ok(typeof executable === "string" && executable, "runner reports its actual execution path");
  const entries = [permission(dirname(executable)), permission(executable)];
  assert.deepEqual(entries.map((entry) => entry.mode), ["700", "600"], "execution directory/file modes must be 0700/0600");
  assert.ok(entries.every((entry) => entry.uid === process.geteuid()), "execution snapshot belongs to runtime UID");
  return entries;
}
// The ordinary user-path lane owns this disposable team's key. Copy only that
// key into the probe HOME, and prove mint authority before diagnosing wake.
function prepareMintAuthority({ seat, fixtureHome, team }) {
  const match = /^([a-z0-9-]+):([a-z0-9.-]+\.test)$/.exec(team);
  assert.ok(match, "mint preflight requires the disposable fixture team");
  assert.equal(resolve(fixtureHome), join(dirname(resolve(seat)), "home"), "mint authority comes from the disposable fixture user home");
  const workspace = createRequire(KERNEL)("yaml").parse(readFileSync(join(seat, ".aw/workspace.yaml"), "utf8"));
  assert.equal(workspace?.aweb_url, env.AWEB_URL, "seat records the local service independently of ambient routing");
  const relativeKey = join(".awid/team-keys", match[2], `${match[1]}.key`);
  const targetKey = join(home, relativeKey);
  mkdirSync(dirname(targetKey), { recursive: true, mode: 0o700 });
  copyFileSync(join(fixtureHome, relativeKey), targetKey);
  chmodSync(targetKey, 0o600);
  const invite = parseObject(aw({ identity: seat, args: ["id", "team", "invite", "--namespace", match[2], "--team", match[1], "--json"] }));
  assert.ok(typeof invite.token === "string" && invite.token, "mint preflight must create a disposable invite; its token is not retained");
  return { team, service: workspace.aweb_url, mint_authority: ProbeOutcome.Passed, invite_cleanup: "disposable team; unconsumed preflight invite removed with the team" };
}
function kernelInstanceStatus() {
  const status = parseObject(oats("status", "--json"));
  assert.ok(Array.isArray(status.agents), "kernel status must list agents");
  const rows = status.agents.flatMap((agent) => { assert.ok(Array.isArray(agent.instances), "each kernel agent must list its instances"); return agent.instances; });
  const row = rows.find((row) => row.home === instanceHome && row.instance === instance);
  assert.ok(row, "kernel must record the probe instance");
  return { status, row };
}
function activeKernelStatus() {
  const { status, row } = kernelInstanceStatus();
  assert.equal(row.running, true, "kernel must report the probe instance active");
  return status;
}
function permission(path) {
  const stat = statSync(path);
  return { path, uid: stat.uid, gid: stat.gid, mode: (stat.mode & 0o7777).toString(8) };
}
let broker, instance, instanceHome;
let brokerErrors = "";
const cleanupErrors = [];
try {
  evidence.kernel = parseObject(oats("--version", "--json"));
  assert.equal(JSON.parse(readFileSync(join(STAGED, "node_modules/@awebai/oats/package.json"), "utf8")).version, artifacts?.kernel.version ?? "0.69.19", "kernel version must match the verified package");
  evidence.kernel_integrity = artifacts?.kernel.integrity ?? JSON.parse(readFileSync(join(STAGED, "package-lock.json"), "utf8")).packages["node_modules/@awebai/oats"].integrity;
  evidence.node = process.version;
  evidence.aw = command({ name: "aw version", argv: [join(bin, "aw"), "version"], output: DiagnosticOutput.Public });
  assert.match(evidence.aw, new RegExp(`commit: ${values["source-commit"]} `), "candidate aw identifies the requested source SHA");
  if (!manual) assert.equal(JSON.parse(readFileSync(join(PROVIDER, "oats.json"), "utf8")).version, PIN.version, "provider version must match the verified release");
  const ref = pathToFileURL(source).href;
  mkdirSync(join(source, "souls/probe"), { recursive: true });
  if (!manual) cpSync(PROVIDER, join(source, "capabilities/oats-aweb"), { recursive: true });
  const messaging = manual ? "" : `defaults:\n  messaging:\n    oats.aweb: { from: local/${source} }\n`;
  writeFileSync(join(source, "oats-workspace.yaml"), `schemaVersion: 2\nname: wake-probe\nmembers:\n  - ${ref}\nlocalTeams: true\n${messaging}`);
  writeFileSync(join(source, "oats-membership.yaml"), `schemaVersion: 2\nworkspace: ${ref}\n`);
  writeFileSync(join(source, "souls/probe/soul.yaml"), `schemaVersion: 2\nname: probe\ndescription: released kernel wake probe\nwork: directory\nlaunch: { harness: ${passiveLaunch.harness} }\n`);
  writeFileSync(join(source, "souls/probe/AGENTS.md"), "Disposable passive wake probe.\n");
  for (const args of [["init", "-q"], ["add", "."], ["commit", "-qm", "owned wake-probe workspace"]]) {
    command({ name: `git ${args[0]}`, argv: ["git", "-C", source, "-c", "user.name=Wake probe", "-c", "user.email=probe@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", ...args], output: DiagnosticOutput.Public });
  }
  const registrySetting = released ? `    registry: ${JSON.stringify(env.AWID_REGISTRY_URL)}\n` : "";
  const deploymentMessaging = manual ? "" : `settings:\n  oats.aweb:\n    delivery: session\n    root: ${JSON.stringify(resolve(values.seat))}\n${registrySetting}`;
  writeFileSync(join(deployment, "oats-local.yaml"), `schemaVersion: 2\nworkspace: ${ref}\nteams:\n  default: { team: ${JSON.stringify(values.team)} }\ndefaultTeam: default\n${deploymentMessaging}launch-configs:\n  passive: ${JSON.stringify(passiveLaunch)}\nsouls:\n  launch:\n    '*': passive\n`);
  if (!manual) evidence.mint_preflight = prepareMintAuthority({ seat: values.seat, fixtureHome: values["fixture-home"], team: values.team });
  // Capture bounded public failure text; credentials remain in the owned volume.
  const startOwnedBroker = () => {
    const child = spawn(join(bin, "aw"), ["wake", "run"], { cwd: home, env, stdio: ["ignore", "ignore", "pipe"] });
    child.on("error", (error) => { brokerErrors += String(error); });
    child.stderr.on("data", (chunk) => { brokerErrors = (brokerErrors + chunk).slice(-16384); });
    return child;
  };
  // A downgraded aw could trust this old stamp; candidate aw must remove it
  // without reading or rewriting the now-unused legacy runner file.
  const state = join(home, ".config/aw/wake"), cache = join(state, "channel-core");
  const legacyBytes = "throw new Error('unused legacy cache must never execute');\n";
  if (!released) {
    mkdirSync(cache, { recursive: true, mode: 0o700 });
    writeFileSync(join(cache, "runner.mjs"), legacyBytes, { mode: 0o600 });
    writeFileSync(join(cache, "runner.sha256"), "old success stamp\n", { mode: 0o600 });
  }
  broker = startOwnedBroker();
  const wakeStatus = () => parseObject(command({ name: "aw wake status", argv: [join(bin, "aw"), "wake", "status", "--json"], cwd: home }));
  await until({ read: wakeStatus, ready: (status) => status.daemon_running === true && status.daemon_pid === broker.pid, label: "isolated broker" });
  const spawnArgs = ["spawn", "probe", "--name", "r20-wake-probe", "--backend", KernelBackend.Tmux];
  if (!released) spawnArgs.push("--no-launch");
  const spawned = parseObject(oats(...spawnArgs, "--json"));
  evidence.kernel_spawn = { ok: spawned.ok, instance: spawned.result?.instance, home: spawned.result?.home };
  assert.equal(spawned.ok, true, "kernel spawn.ok must confirm the spawn");
  ({ instance, home: instanceHome } = spawned.result);
  assert.ok(instance && instanceHome, "kernel spawn must return its instance and home");
  if (manual) {
    command({ name: "aw wake register", argv: [join(bin, "aw"), "wake", "register", "--home", instanceHome,
      "--identity-home", join(resolve(values["aw-actor"]), ".aw"), "--delivery", "session", "--backend", "tmux"] });
  }
  const runnerReady = (status) => status.daemon_running === true && status.daemon_pid === broker.pid && wakeInstances(status).some((row) => row.home === instanceHome && row.channel_core?.running === true);
  let prelaunchRow;
  if (!released) {
    const beforeLaunch = kernelInstanceStatus();
    evidence.kernel_status_before = beforeLaunch.status;
    assert.equal(beforeLaunch.row.running, false, "a no-launch instance is recorded without a running session");
    const prelaunchKernel = parseObject(oats("session", "inspect", "--home", instanceHome, "--json"));
    evidence.kernel_prelaunch = kernelSessionSnapshot(prelaunchKernel);
    assert.equal(prelaunchKernel.result.state, "not-launched", "kernel prelaunch.state must be not-launched");
    const prelaunch = await until({ read: wakeStatus, ready: (status) => runnerReady(status) && wakeInstances(status).some((row) => row.home === instanceHome && row.last_state === "not-launched" && row.channel_core.readiness_state === "not-launched"), label: "prelaunch observation and ready handshake before process creation" });
    evidence.wake_prelaunch = prelaunch;
    prelaunchRow = wakeInstances(prelaunch).find((row) => row.home === instanceHome);
    assert.equal(prelaunchRow.phase, "pending", "wake prelaunch.phase must be pending before session creation");
    const started = parseObject(oats("session", "start", "--home", instanceHome, "--json"));
    evidence.kernel_start = { ok: typeof started.ok === "boolean" ? started.ok : null };
    assert.equal(started.ok, true, "kernel session start.ok must confirm launch");
  }
  const liveKernel = parseObject(oats("session", "inspect", "--home", instanceHome, "--json"));
  evidence.kernel_started_idle = kernelSessionSnapshot(liveKernel);
  assert.equal(liveKernel.result.present, true, "kernel started_idle.present must be true before quiet wake readiness");
  assert.equal(liveKernel.result.running, true, "kernel started_idle.running must be true before quiet wake readiness");
  evidence.kernel_status_started_idle = activeKernelStatus();
  const fresh = await until({ read: wakeStatus, ready: (status) => runnerReady(status) && (released ||
    (wakeInstances(status).some((row) => row.home === instanceHome && row.phase === "active") &&
     status.readiness?.some((verdict) => verdict.home === instanceHome && verdict.ready === true))), label: "quiet startup readiness before any mail" });
  evidence.wake_fresh = fresh;
  const freshRow = wakeInstances(fresh).find((row) => row.home === instanceHome);
  let before = fresh;
  if (!released) {
    // Go omits generation=0 and serializes time.Time's zero as a nonempty string.
    assert.equal(freshRow.channel_core.generation ?? 0, prelaunchRow.channel_core.generation ?? 0, "quiet startup must keep the registered runner generation");
    assert.ok(prelaunchRow.channel_core.last_run_at && !wakeTimestampIsUnset(prelaunchRow.channel_core.last_run_at), "prelaunch runner must have a recorded start time");
    assert.equal(freshRow.channel_core.last_run_at, prelaunchRow.channel_core.last_run_at, "quiet startup must keep the same runner process start");
    assert.ok(wakeTimestampIsUnset(freshRow.channel_core.last_input_at), "startup inspection submits no input");
    await sleep(1000);
    const idle = wakeStatus();
    evidence.wake_idle_after_presence = idle;
    const idleRow = wakeInstances(idle).find((row) => row.home === instanceHome);
    assert.equal(idleRow.last_inspect_at, freshRow.last_inspect_at, "startup observer stops after first live observation");
    assert.ok(wakeTimestampIsUnset(idleRow.channel_core.last_input_at), "idle startup needs no delivery event");
    evidence.private_execution_fresh = executionPermissions(fresh);
    assert.equal(existsSync(join(cache, "runner.sha256")), false, "candidate removes the legacy stamp");
    assert.equal(readFileSync(join(cache, "runner.mjs"), "utf8"), legacyBytes, "candidate leaves unused legacy bytes alone");
    evidence.legacy_cache = { stamp_removed: true, runner_unchanged: true };
    evidence.permissions_fresh = [join(home, ".config/aw"), state, cache].map(permission);
    await stopOwnedBroker(broker);
    chmodSync(state, 0o770);
    chmodSync(cache, 0o770);
    chmodSync(join(cache, "runner.mjs"), 0o660);
    evidence.storage_mode_setup = "owned fixture emulates group-write widening; not a Kubernetes/PVC qualification";
    broker = startOwnedBroker();
    before = await until({ read: wakeStatus, ready: runnerReady, label: "runner restart with group-widened data cache" });
    evidence.wake_before = before;
    evidence.kernel_status_after_group_widening = activeKernelStatus();
    evidence.private_execution_after_group_widening = executionPermissions(before);
    evidence.permissions_before = [join(home, ".config/aw"), state, cache, join(cache, "runner.mjs")].map(permission);
  }
  const identity = manual ? resolve(values["aw-actor"]) : instanceHome;
  const address = parseObject(aw({ identity, args: ["whoami", "--json"] }));
  const recipient = address.address || address.alias || address.name;
  assert.ok(typeof recipient === "string" && recipient, "spawned seat must be addressable");
  recordLifecycle("join", { recipient, team: values.team, session: kernelSessionSnapshot(liveKernel) });
  const subject = manual ? "Released aw native broker wake" : "R20 released-kernel wake probe";
  const mailBody = "Disposable wake-path qualification; no action.";
  const sent = parseObject(aw({ identity: values.sender, args: ["mail", "send", "--to", recipient, "--subject", subject, "--body", mailBody, "--json"] }));
  assert.ok(sent.message_id, "mail send must return its message id");
  evidence.message_id = sent.message_id;
  evidence.wake_after = await until({ read: wakeStatus, ready: (status) => wakeInstances(status).some((row) => row.home === instanceHome && row.channel_core?.last_input_at && !wakeTimestampIsUnset(row.channel_core.last_input_at) && row.channel_core.last_input_at !== wakeInstances(before).find((entry) => entry.home === instanceHome)?.channel_core?.last_input_at), label: "broker input receipt" });
  const capture = () => {
    const panes = command({ name: "tmux list-panes", argv: [...OWNED_TMUX, "list-panes", "-a", "-F", "#{pane_id}"] }).trim().split("\n");
    assert.ok(panes.length && panes.every((pane) => /^%[0-9]+$/.test(pane)), "owned kernel server reports valid panes");
    return panes.map((pane) => command({ name: "tmux capture-pane", argv: [...OWNED_TMUX, "capture-pane", "-p", "-S", "-400", "-t", pane] })).join("\n");
  };
  evidence.presented_wake = await until({ read: capture, ready: (text) => text.includes(sent.message_id) && text.includes(subject), label: "fresh wake in the isolated kernel session" });
  if (manual) {
    const mailView = parseObject(aw({ identity, args: ["mail", "show", "--conversation-id", sent.conversation_id, "--json"] }));
    const mail = (mailView.messages || []).find((message) => message.message_id === sent.message_id);
    assert.equal(mail?.body, mailBody, "the registered released aw identity reads the exact presented mail");
    recordLifecycle("wake", { subject, event: "mail", presented_through: "tmux", registration: "aw wake register",
      verification_status: mail.verification_status });
  } else if (released) {
    const mailView = parseObject(aw({ identity: instanceHome, args: ["mail", "show", "--conversation-id", sent.conversation_id, "--json"] }));
    const mail = (mailView.messages || []).find((message) => message.message_id === sent.message_id);
    assert.equal(mail?.body === mailBody, true, "released OATS identity reads the presented mail");
    recordLifecycle("mail", { subject, body: mail.body, verification_status: mail.verification_status, content_mode: mail.content_mode });
    recordLifecycle("wake", { subject, event: "mail", presented_through: "tmux", native_broker: true });
    const chatBody = "Released OATS chat on the RC validation team.";
    const chat = parseObject(aw({ identity: values.sender, args: ["chat", "send-and-wait", recipient, chatBody, "--plaintext", "--wait", "0", "--json"] }));
    assert.ok(chat.session_id && chat.message_id, "released OATS chat must return a session and message");
    evidence.presented_chat = await until({ read: capture, ready: (text) => text.includes(chat.message_id) && text.includes(chatBody), label: "chat wake in the isolated kernel session" });
    const chatView = parseObject(aw({ identity: instanceHome, args: ["chat", "history", "--session-id", chat.session_id, "--json"] }));
    const received = (chatView.messages || []).find((message) => message.message_id === chat.message_id);
    assert.equal(received?.body === chatBody, true, "released OATS identity reads the presented chat");
    recordLifecycle("chat", { body: received.body, verification_status: received.verification_status, content_mode: received.content_mode });
  } else {
    evidence.permissions_after = [join(home, ".config/aw"), state, cache].map(permission);
  }
  evidence.kernel_events = oats("instance", "events", instance, "--json");
  evidence.kernel_status_after = activeKernelStatus();
  evidence.result = ProbeOutcome.Passed;
} catch (error) {
  evidence.result = ProbeOutcome.Failed;
  evidence.error = String(error);
  if (error.diagnostic) evidence.failed_command = error.diagnostic;
  process.exitCode = 1;
} finally {
  if (instanceHome && manual) {
    try { command({ name: "aw wake deregister", argv: [join(bin, "aw"), "wake", "deregister", "--home", instanceHome] }); }
    catch (error) { cleanupErrors.push(String(error)); }
  }
  if (instance) {
    try {
      // Plain retire --json in released 0.69.19 returns the receipt directly.
      evidence.retire = parseObject(oats("retire", instance, "--json"));
      assert.equal(evidence.retire.retired, instance, "retire.retired must name the owned instance");
      assert.equal(evidence.retire.removedDir, true, "retire.removedDir must confirm home removal");
      assert.ok(!evidence.retire.rollbackIncomplete, "retire must not leave rollback incomplete");
      assert.ok(!evidence.retire.forcedIncomplete, "retire must not force past incomplete cleanup");
      assert.equal(existsSync(instanceHome), false, "retired instance home must be absent");
      if (!manual) {
        assert.equal(evidence.retire.capabilityMeta?.["oats.aweb"]?.retired, true, "provider retirement must confirm completed coordination and revocation");
        const provider = evidence.retire.capabilityMeta["oats.aweb"];
        if (released && provider.aliasReusable === false && provider.aliasReason === "team_not_hosted") {
          const pending = provider.pendingControllerCleanup?.find((row) => row.team === values.team && row.alias === instance);
          assert.ok(pending?.certificateId, "released OATS must identify the certificate for remaining owner cleanup");
          const [team, domain] = values.team.split(":");
          aw({ identity: values.seat, args: ["id", "team", "remove-member", "--namespace", domain, "--team", team,
            "--cert-id", pending.certificateId, "--json"] });
        } else {
          assert.equal(provider.aliasReusable, true, "provider retirement must confirm the alias is reusable");
        }
        if (released) {
          const observed = parseObject(aw({ identity: values.seat, args: ["team", "admin", "agent-status", instance, "--json"] }));
          assert.equal(observed.state, "clear", "controller readback proves retirement");
          assert.equal(observed.name_reusable, true, "controller readback proves alias reuse");
          recordLifecycle("retire", { retired: evidence.retire.retired, removedDir: evidence.retire.removedDir,
            retiredByProvider: provider.retired, aliasReusable: provider.aliasReusable, aliasReason: provider.aliasReason,
            state: observed.state, name_reusable: observed.name_reusable });
        }
      }
    } catch (error) { cleanupErrors.push(String(error)); }
  }
  await stopOwnedBroker(broker);
  try { cleanupPassiveTerminal({ root, tmuxBinary: OWNED_TMUX[0], env }); } catch (error) { cleanupErrors.push(String(error)); }
  evidence.cleanup_errors = cleanupErrors;
  if (evidence.result === ProbeOutcome.Failed) evidence.broker_stderr = brokerErrors;
  if (cleanupErrors.length) { evidence.result = ProbeOutcome.Failed; process.exitCode = 1; }
  mkdirSync(dirname(values.output), { recursive: true });
  writeFileSync(values.output, JSON.stringify(evidence, null, 2) + "\n");
}
assert.equal(evidence.result, ProbeOutcome.Passed, `released-kernel-wake result must be PASSED: ${evidence.failed_check || "inspect recorded diagnostics"}`);
console.log("PASS released OATS kernel -> candidate aw wake path");
