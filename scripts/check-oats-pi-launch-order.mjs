#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const oatsRoot = process.env.OATS_TEST_ROOT ? realpathSync(resolve(process.env.OATS_TEST_ROOT)) : "";
const oatsCli = oatsRoot && join(oatsRoot, "bin", "oats.mjs");
const contributedArgument = "--append-system-prompt";
const executionVariable = "OATS_RUN_REAL_PI_LAUNCH_ORDER";
const responseMarker = "OATS_PI_LAUNCH_ORDER_OK";

function fail(message) {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(1);
}

function write(path, content, mode) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, mode === undefined ? undefined : { mode });
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env || process.env,
    encoding: "utf8",
    stdio: options.inherit ? "inherit" : ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    const output = options.inherit ? "" : [result.stdout, result.stderr].filter(Boolean).join("\n");
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}${output ? `:\n${output}` : ""}`);
  }
  return result;
}

function initializeRepository(repo) {
  mkdirSync(repo, { recursive: true });
  run("git", ["init", "-q", repo]);
  run("git", ["-C", repo, "config", "user.email", "launch-order@example.invalid"]);
  run("git", ["-C", repo, "config", "user.name", "Launch Order Gate"]);
}

function createFixture(base, path, model = "") {
  const repo = join(base, "repo");
  const agentsRoot = join(base, "agents");
  const soul = join(agentsRoot, "probe", "soul");
  initializeRepository(repo);
  write(join(repo, ".gitignore"), "\n");
  write(join(soul, "soul.yaml"), [
    "name: probe",
    "kind: persistent",
    `repo: ${repo}`,
    "work: checkout",
    "runtime: pi",
    ...(model ? [`model: ${model}`] : []),
    "",
  ].join("\n"));
  write(join(soul, "AGENTS.md"), "# Pi launch-order probe\n");
  mkdirSync(join(agentsRoot, "probe", "instances"), { recursive: true });

  const capability = join(repo, ".agents", "capabilities", "owned", "launch-order-probe");
  write(join(capability, "oats.json"), JSON.stringify({
    capability: "aweb.launch-order-probe",
    version: "1.0.0",
    compatibility: { oats: ">=0.6.2" },
    description: "Contributes a trailing variadic Pi argument for the release gate.",
    hooks: { spawn: "hook.mjs" },
  }, null, 2) + "\n");
  write(
    join(capability, "hook.mjs"),
    `console.log(JSON.stringify({ launch: { pi: ${JSON.stringify(contributedArgument)} } }));\n`,
  );
  write(join(repo, "oats-config.yaml"), [
    "capabilities:",
    "  additive:",
    "    aweb.launch-order-probe:",
    "      global: true",
    "",
  ].join("\n"));
  run("git", ["-C", repo, "add", "."]);
  run("git", ["-C", repo, "commit", "-qm", "launch-order fixture"]);
  return { repo, agentsRoot, path };
}

function parseSpawn(result) {
  let document;
  try {
    document = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`OATS spawn did not return JSON: ${error.message}\n${result.stdout}\n${result.stderr}`);
  }
  const spawned = document.schemaVersion === 1 ? document.result : document;
  if (!spawned?.home) throw new Error(`OATS spawn returned no instance home: ${result.stdout}`);
  return spawned;
}

function spawnProbe(fixture, env, launch) {
  const args = [
    oatsCli,
    "spawn",
    "probe",
    "--purpose",
    launch ? "pi-order-execution" : "pi-order-construction",
    "--task",
    `Reply with exactly ${responseMarker} and no other text.`,
    "--json",
  ];
  if (!launch) args.splice(args.length - 1, 0, "--no-launch");
  return parseSpawn(run(process.execPath, args, { cwd: fixture.repo, env }));
}

function assertConstructedOrder(spawned) {
  const instance = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  const command = String(instance.command || "");
  const taskIndex = command.indexOf("@TASK.md");
  const contributedIndex = command.lastIndexOf(contributedArgument);
  if (taskIndex < 0) throw new Error(`constructed Pi command has no @TASK.md positional: ${command}`);
  if (contributedIndex < 0) throw new Error(`constructed Pi command has no contributed ${contributedArgument}: ${command}`);
  if (taskIndex > contributedIndex) {
    throw new Error(`constructed Pi task positional follows the trailing variadic contributed argument: ${command}`);
  }
  return command;
}

function constructionCheck() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oats-pi-order-construction-")));
  try {
    const bin = join(base, "bin");
    write(join(bin, "pi"), "#!/bin/sh\nexit 0\n", 0o755);
    const fixture = createFixture(base, `${bin}${delimiter}${process.env.PATH}`);
    const env = {
      ...process.env,
      PATH: fixture.path,
      PI_AGENTS_ROOT: fixture.agentsRoot,
    };
    const spawned = spawnProbe(fixture, env, false);
    assertConstructedOrder(spawned);
    process.stdout.write("OATS Pi launch-order construction: PASS (pinned CLI --no-launch spawn)\n");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

function sessionFiles(root) {
  if (!existsSync(root)) return [];
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...sessionFiles(path));
    else if (entry.isFile() && entry.name.endsWith(".jsonl")) files.push(path);
  }
  return files;
}

function assistantAnswered(path) {
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      continue;
    }
    const message = record?.message;
    if (message?.role !== "assistant") continue;
    if (JSON.stringify(message.content).includes(responseMarker)) return true;
  }
  return false;
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

export function isolatedExecutionEnvironment(ambient, overrides) {
  const env = { ...ambient, ...overrides };
  delete env.TMUX;
  return env;
}

function systemTmux(args, env) {
  return spawnSync("tmux", args, { env, encoding: "utf8" });
}

function tmuxSessionNames(env, runTmux) {
  const result = runTmux(["list-sessions", "-F", "#{session_name}"], env);
  if (result.status === 0) {
    return String(result.stdout || "").split("\n").map((name) => name.trim()).filter(Boolean);
  }
  const detail = String(result.stderr || "").trim();
  const knownAbsent = result.status === 1 && (
    /no server running on/i.test(detail)
    || /error connecting to .*\(No such file or directory\)/i.test(detail)
  );
  if (knownAbsent) return [];
  throw new Error(`could not establish isolated tmux session state (status ${result.status}): ${detail || "no diagnostic"}`);
}

export function cleanupTmuxSession(session, env, runTmux = systemTmux) {
  const before = tmuxSessionNames(env, runTmux);
  if (!before.includes(session)) return;

  const removed = runTmux(["kill-session", "-t", `=${session}`], env);
  if (removed.status !== 0) {
    throw new Error(`could not remove isolated tmux session ${session}: ${String(removed.stderr || "").trim() || "no diagnostic"}`);
  }
  const after = tmuxSessionNames(env, runTmux);
  if (after.includes(session)) {
    throw new Error(`isolated tmux session ${session} remained after kill-session`);
  }
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

export function finalizeExecutionArtifacts({
  base,
  authPath,
  session,
  env,
  tmuxAttempted,
  runTmux = systemTmux,
}) {
  rmSync(authPath, { force: true });
  if (!tmuxAttempted) {
    rmSync(base, { recursive: true, force: true });
    return;
  }

  try {
    cleanupTmuxSession(session, env, runTmux);
  } catch (error) {
    const tmuxDirectory = env.TMUX_TMPDIR;
    const guard = join(repoRoot, "scripts", "guard-bin", "tmux");
    throw new Error(
      `${error.message}; copied Pi auth was removed, but retained isolated tmux evidence at ${base}. `
      + `Inspect or retry manually: env -u TMUX TMUX_TMPDIR=${shellQuote(tmuxDirectory)} ${shellQuote(guard)} kill-session -t ${shellQuote(`=${session}`)}`,
    );
  }
  rmSync(base, { recursive: true, force: true });
}

export function executionCheck({
  ambientEnv = process.env,
  authSource: explicitAuthSource,
  model: explicitModel,
  spawnExecutionProbe = (fixture, env) => spawnProbe(fixture, env, true),
  runTmux = systemTmux,
  timeoutMs = 180_000,
  reportPass = (message) => process.stdout.write(message),
} = {}) {
  const expectedGuard = realpathSync(join(repoRoot, "scripts", "guard-bin"));
  const firstPathEntry = realpathSync((ambientEnv.PATH || "").split(delimiter)[0]);
  if (firstPathEntry !== expectedGuard) {
    throw new Error(`real Pi execution requires ${expectedGuard} first on PATH`);
  }

  const base = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oats-pi-order-execution-")));
  const home = join(base, "home");
  const piConfig = join(home, ".pi", "agent");
  const authPath = join(piConfig, "auth.json");
  const tmuxDirectory = join(base, "tmux");
  const tmuxSession = `aweb-oats-pi-order-${process.pid}`;
  const hostConfig = ambientEnv.PI_CODING_AGENT_DIR || join(ambientEnv.HOME || "", ".pi", "agent");
  const authSource = explicitAuthSource || ambientEnv.OATS_PI_LAUNCH_ORDER_AUTH || join(hostConfig, "auth.json");
  const model = explicitModel || ambientEnv.OATS_PI_LAUNCH_ORDER_MODEL || "openai-codex/gpt-5.4-mini:minimal";
  let executionEnv;
  let executionError;
  let tmuxAttempted = false;
  try {
    if (!existsSync(authSource)) throw new Error(`real Pi authentication not found at ${authSource}`);
    mkdirSync(join(piConfig, "sessions"), { recursive: true });
    mkdirSync(tmuxDirectory, { recursive: true });
    copyFileSync(authSource, authPath);
    chmodSync(authPath, 0o600);

    const fixture = createFixture(base, ambientEnv.PATH, model);
    executionEnv = isolatedExecutionEnvironment(ambientEnv, {
      HOME: home,
      PI_CODING_AGENT_DIR: piConfig,
      PI_AGENTS_ROOT: fixture.agentsRoot,
      PI_AGENTS_TMUX_SESSION: tmuxSession,
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
      TMUX_TMPDIR: tmuxDirectory,
    });
    tmuxAttempted = true;
    const spawned = spawnExecutionProbe(fixture, executionEnv);
    assertConstructedOrder(spawned);

    const deadline = Date.now() + timeoutMs;
    let observed = false;
    while (Date.now() < deadline && !observed) {
      observed = sessionFiles(join(piConfig, "sessions")).some(assistantAnswered);
      if (!observed) sleep(1_000);
    }
    if (!observed) {
      throw new Error(`real Pi produced no assistant ${responseMarker} response within ${Math.ceil(timeoutMs / 1_000)} seconds`);
    }
    reportPass("OATS Pi launch-order execution: PASS (real Pi parsed and answered the spawned task)\n");
  } catch (error) {
    executionError = error;
  }

  let cleanupError;
  try {
    finalizeExecutionArtifacts({ base, authPath, session: tmuxSession, env: executionEnv, tmuxAttempted, runTmux });
  } catch (error) {
    cleanupError = error;
  }
  if (executionError && cleanupError) {
    throw new Error(
      `real Pi execution failed: ${executionError.message}\n`
      + `isolated tmux cleanup was not established: ${cleanupError.message}`,
    );
  }
  if (cleanupError) throw cleanupError;
  if (executionError) throw executionError;
}

export function main() {
  if (!oatsRoot || !existsSync(oatsCli)) {
    fail(`OATS_TEST_ROOT must contain the pinned OATS CLI: ${oatsCli || "<unset>"}`);
  }

  try {
    constructionCheck();
    if (process.env[executionVariable] === "1") {
      process.stderr.write("OATS Pi launch-order execution: RUNNING (real runtime; network and model tokens will be used)\n");
      executionCheck();
    } else {
      process.stderr.write(
        `OATS Pi launch-order execution: SKIPPED (${executionVariable}=1 was not set); construction only, real Pi runtime was not executed.\n`,
      );
    }
  } catch (error) {
    fail(error.stack || error.message);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main();
}
