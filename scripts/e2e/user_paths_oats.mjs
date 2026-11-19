// Released OATS kernel -> candidate aw wake seam. The fixture construction uses
// oats-aweb v1.42.1 test/resident-journey.test.mjs's real local-member workspace.
// A supported passive launch executable avoids a model call, per OATS's launch
// configuration contract. Neither the kernel, provider, aw nor broker is faked.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const ProbeOutcome = Object.freeze({ Passed: "PASSED", Failed: "FAILED" });
const STAGED = "/opt/user-paths/released-oats";
const KERNEL = join(STAGED, "node_modules/@awebai/oats/bin/oats.mjs");
const PROVIDER = "/opt/user-paths/oats-aweb/oats-package/capabilities/oats-aweb";
const PIN = JSON.parse(readFileSync(join(STAGED, "provider.json"), "utf8"));
const { values } = parseArgs({ options: {
  aw: { type: "string" }, root: { type: "string" }, seat: { type: "string" },
  sender: { type: "string" }, team: { type: "string" }, output: { type: "string" },
  "source-commit": { type: "string" },
} });
for (const option of ["aw", "root", "seat", "sender", "team", "output", "source-commit"]) {
  assert.ok(values[option], `--${option} is required`);
}
const root = resolve(values.root);
const home = join(root, "home"), deployment = join(root, "deploy"), source = join(root, "source"), bin = join(root, "bin");
for (const path of [home, deployment, source, bin, join(root, "tmux")]) mkdirSync(path, { recursive: true, mode: 0o700 });
const evidence = { scope: "released OATS kernel -> candidate aw wake path; not the lab image, supervisor or Helm storage", provider: PIN, candidate_source_commit: values["source-commit"], candidate_binary_sha256: createHash("sha256").update(readFileSync(values.aw)).digest("hex"), process_uid: process.geteuid(), process_gid: process.getegid() };
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
writeFileSync(join(bin, "passive-session"), "#!/bin/sh\nexec sleep infinity\n", { mode: 0o700 });
function command({ argv, cwd = deployment, timeout = 60000 }) {
  const result = spawnSync(argv[0], argv.slice(1), { cwd, env, encoding: "utf8", timeout });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${argv.slice(0, 3).join(" ")}: exit=${result.status}: ${result.stderr}`);
  return result.stdout;
}
const oats = (...argv) => command({ argv: [process.execPath, KERNEL, ...argv] });
const aw = ({ identity, args }) => command({ argv: [join(bin, "aw"), "--identity-home", join(identity, ".aw"), ...args], cwd: identity });
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
function permission(path) {
  const stat = statSync(path);
  return { path, uid: stat.uid, gid: stat.gid, mode: (stat.mode & 0o7777).toString(8) };
}
let broker, instance, instanceHome;
let brokerErrors = "";
const cleanupErrors = [];
try {
  evidence.kernel = parseObject(oats("--version", "--json"));
  assert.equal(JSON.parse(readFileSync(join(STAGED, "node_modules/@awebai/oats/package.json"), "utf8")).version, "0.69.19");
  evidence.kernel_integrity = JSON.parse(readFileSync(join(STAGED, "package-lock.json"), "utf8")).packages["node_modules/@awebai/oats"].integrity;
  evidence.node = process.version;
  evidence.aw = command({ argv: [join(bin, "aw"), "version"] });
  assert.match(evidence.aw, new RegExp(`commit: ${values["source-commit"]} `), "candidate aw identifies the requested source SHA");
  assert.equal(JSON.parse(readFileSync(join(PROVIDER, "oats.json"), "utf8")).version, PIN.version);
  const ref = pathToFileURL(source).href;
  mkdirSync(join(source, "souls/probe"), { recursive: true });
  cpSync(PROVIDER, join(source, "capabilities/oats-aweb"), { recursive: true });
  writeFileSync(join(source, "oats-workspace.yaml"), `schemaVersion: 2\nname: wake-probe\nmembers:\n  - ${ref}\nlocalTeams: true\ndefaults:\n  messaging:\n    oats.aweb: { from: local/${source} }\n`);
  writeFileSync(join(source, "oats-membership.yaml"), `schemaVersion: 2\nworkspace: ${ref}\n`);
  writeFileSync(join(source, "souls/probe/soul.yaml"), "schemaVersion: 2\nname: probe\ndescription: released kernel wake probe\nwork: directory\nlaunch: { harness: claude }\n");
  writeFileSync(join(source, "souls/probe/AGENTS.md"), "Disposable passive wake probe.\n");
  for (const args of [["init", "-q"], ["add", "."], ["commit", "-qm", "owned wake-probe workspace"]]) {
    command({ argv: ["git", "-C", source, "-c", "user.name=Wake probe", "-c", "user.email=probe@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", ...args] });
  }
  writeFileSync(join(deployment, "oats-local.yaml"), `schemaVersion: 2\nworkspace: ${ref}\nteams:\n  default: { team: ${JSON.stringify(values.team)} }\ndefaultTeam: default\nsettings:\n  oats.aweb:\n    delivery: session\n    root: ${JSON.stringify(resolve(values.seat))}\nlaunch-configs:\n  passive:\n    harness: claude\n    executable: ${JSON.stringify(join(bin, "passive-session"))}\nsouls:\n  launch:\n    '*': passive\n`);
  const brokerLog = join(root, "broker.log");
  // Capture bounded public failure text; credentials remain in the owned volume.
  broker = spawn(join(bin, "aw"), ["wake", "run"], { cwd: home, env, stdio: ["ignore", "ignore", "pipe"] });
  broker.stderr.on("data", (chunk) => { brokerErrors = (brokerErrors + chunk).slice(-16384); });
  const wakeStatus = () => parseObject(command({ argv: [join(bin, "aw"), "wake", "status", "--json"], cwd: home }));
  await until({ read: wakeStatus, ready: (status) => status.daemon_running === true, label: "isolated broker" });
  const spawned = parseObject(oats("spawn", "probe", "--name", "r20-wake-probe", "--json"));
  assert.equal(spawned.ok, true);
  ({ instance, home: instanceHome } = spawned.result);
  assert.ok(instance && instanceHome, "kernel spawn must return its instance and home");
  evidence.kernel_status_before = parseObject(oats("status", "--json"));
  const before = await until({ read: wakeStatus, ready: (status) => wakeInstances(status).some((row) => row.home === instanceHome && row.channel_core?.running === true), label: "kernel-registered wake runner" });
  evidence.wake_before = before;
  const executable = wakeInstances(before).find((row) => row.home === instanceHome)?.channel_core?.bundle_path;
  assert.ok(typeof executable === "string" && executable, "runner reports its actual execution path");
  evidence.private_execution = [permission(dirname(executable)), permission(executable)];
  assert.deepEqual(evidence.private_execution.map((entry) => entry.mode), ["700", "600"]);
  assert.ok(evidence.private_execution.every((entry) => entry.uid === process.geteuid()), "execution snapshot belongs to runtime UID");
  const state = join(home, ".config/aw/wake"), cache = join(state, "channel-core");
  evidence.permissions_before = [join(home, ".config/aw"), state, cache].map(permission);
  const address = parseObject(aw({ identity: instanceHome, args: ["whoami", "--json"] }));
  const recipient = address.address || address.alias || address.name;
  assert.ok(typeof recipient === "string" && recipient, "spawned seat must be addressable");
  const subject = "R20 released-kernel wake probe";
  const sent = parseObject(aw({ identity: values.sender, args: ["mail", "send", "--to", recipient, "--subject", subject, "--body", "Disposable wake-path qualification; no action.", "--json"] }));
  assert.ok(sent.message_id, "mail send must return its message id");
  evidence.message_id = sent.message_id;
  evidence.wake_after = await until({ read: wakeStatus, ready: (status) => wakeInstances(status).some((row) => row.home === instanceHome && row.channel_core?.last_input_at && row.channel_core.last_input_at !== wakeInstances(before).find((entry) => entry.home === instanceHome)?.channel_core?.last_input_at), label: "broker input receipt" });
  const capture = () => {
    const panes = command({ argv: ["tmux", "-L", "oats", "list-panes", "-a", "-F", "#{pane_id}"] }).trim().split("\n");
    assert.ok(panes.length && panes.every((pane) => /^%[0-9]+$/.test(pane)), "owned kernel server reports valid panes");
    return panes.map((pane) => command({ argv: ["tmux", "-L", "oats", "capture-pane", "-p", "-S", "-400", "-t", pane] })).join("\n");
  };
  evidence.presented_wake = await until({ read: capture, ready: (text) => text.includes(sent.message_id) && text.includes(subject), label: "fresh wake in the isolated kernel session" });
  evidence.permissions_after = [join(home, ".config/aw"), state, cache].map(permission);
  evidence.kernel_events = oats("instance", "events", instance, "--json");
  evidence.kernel_status_after = parseObject(oats("status", "--json"));
  writeFileSync(brokerLog, brokerErrors);
  evidence.result = ProbeOutcome.Passed;
} catch (error) {
  evidence.result = ProbeOutcome.Failed;
  evidence.error = String(error);
  process.exitCode = 1;
} finally {
  if (instance) { try { evidence.retire = parseObject(oats("retire", instance, "--json")); } catch (error) { cleanupErrors.push(String(error)); } }
  if (broker) {
    if (broker.exitCode === null && broker.signalCode === null) {
      const exited = new Promise((done) => broker.once("exit", done));
      broker.kill("SIGTERM");
      await Promise.race([exited, sleep(8000)]);
      if (broker.exitCode === null && broker.signalCode === null) { broker.kill("SIGKILL"); await exited; }
    }
  }
  const stopped = spawnSync("tmux", ["-L", "oats", "kill-server"], { cwd: deployment, env, encoding: "utf8" });
  if (stopped.error || (stopped.status !== 0 && !/no server running|No such file or directory/.test(stopped.stderr))) cleanupErrors.push(String(stopped.error || stopped.stderr));
  evidence.cleanup_errors = cleanupErrors;
  if (evidence.result === ProbeOutcome.Failed) evidence.broker_stderr = brokerErrors;
  if (cleanupErrors.length) { evidence.result = ProbeOutcome.Failed; process.exitCode = 1; }
  mkdirSync(dirname(values.output), { recursive: true });
  writeFileSync(values.output, JSON.stringify(evidence, null, 2) + "\n");
  rmSync(root, { recursive: true, force: true });
}
assert.equal(evidence.result, ProbeOutcome.Passed, evidence.error || JSON.stringify(cleanupErrors));
console.log("PASS released OATS kernel -> candidate aw wake path");
