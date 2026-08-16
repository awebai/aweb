import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";
import { oatsCliPath } from "./helpers/oats-test-root.mjs";

const CAPABILITY_SOURCE = resolve(new URL("../.agents/capabilities/owned/aweb-tasks", import.meta.url).pathname);
const CANONICAL_SKILL = resolve(new URL("../../skills/aweb-coordination", import.meta.url).pathname);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oats-tasks-")));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function oatsCli() {
  return oatsCliPath();
}

test("aweb tasks capability owns the exclusive tasks and roster contract", () => {
  const manifest = JSON.parse(readFileSync(join(CAPABILITY_SOURCE, "oats.json"), "utf8"));
  assert.equal(manifest.capability, "aweb.tasks");
  assert.equal(manifest.layer, "tasks");
  assert.deepEqual(manifest.skills, ["skills/aweb-coordination"]);
  assert.equal(manifest.inject, "injects/aweb-tasks.md");
  assert.deepEqual(manifest.requires, [{
    command: "aw",
    why: "shared task queue, work discovery, ownership, status, and team roster",
    install: "https://aweb.ai/docs",
  }]);

  const injection = readFileSync(join(CAPABILITY_SOURCE, manifest.inject), "utf8");
  for (const statement of [
    "aw task",
    "aw work",
    "aw workspace status",
    "authoritative",
    "Do not use task or roster features from the messaging\\s+layer",
  ]) {
    assert.match(injection, new RegExp(statement));
  }

  for (const relative of ["SKILL.md", "references/coordination-patterns.md"]) {
    assert.equal(
      readFileSync(join(CAPABILITY_SOURCE, "skills", "aweb-coordination", relative), "utf8"),
      readFileSync(join(CANONICAL_SKILL, relative), "utf8"),
      `capability skill copy drifted: ${relative}`,
    );
  }
});

test("real OATS spawn composes the aweb tasks integration into the instance", () => {
  const base = temporaryDirectory();
  const repo = join(base, "repo");
  const agentsRoot = join(base, "agents");
  const soul = join(agentsRoot, "developer", "soul");
  mkdirSync(repo, { recursive: true });
  write(join(soul, "soul.yaml"), `name: developer\nkind: persistent\nrepo: ${repo}\nwork: checkout\nruntime: pi\n`);
  write(join(soul, "AGENTS.md"), "# Developer\n");
  mkdirSync(join(agentsRoot, "developer", "instances"), { recursive: true });
  cpSync(CAPABILITY_SOURCE, join(repo, ".agents", "capabilities", "owned", "aweb-tasks"), { recursive: true });
  write(join(repo, "oats-config.yaml"), [
    "capabilities:",
    "  layers:",
    "    tasks:",
    "      capability: aweb.tasks",
    "      global:",
    "        enabled: true",
    "",
  ].join("\n"));
  execFileSync("git", ["init", "-q", repo]);
  execFileSync("git", ["-C", repo, "config", "user.email", "test@example.invalid"]);
  execFileSync("git", ["-C", repo, "config", "user.name", "Test"]);
  execFileSync("git", ["-C", repo, "add", "."]);
  execFileSync("git", ["-C", repo, "commit", "-qm", "configure aweb tasks"]);

  const result = spawnSync(process.execPath, [oatsCli(), "spawn", "developer", "--purpose", "tasks-binding", "--no-launch", "--json"], {
    cwd: repo,
    env: { ...process.env, PI_AGENTS_ROOT: agentsRoot },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, [result.stderr, result.stdout].filter(Boolean).join("\n"));
  const document = JSON.parse(result.stdout);
  const spawned = document.schemaVersion === 1 ? document.result : document;
  assert.match(readFileSync(join(spawned.home, "AGENTS.md"), "utf8"), /## Tasks: aweb/);
  assert.equal(existsSync(join(spawned.home, ".agents", "skills", "aweb-coordination", "SKILL.md")), true);
  const instance = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  const composedSkill = instance.skills.find((skill) => skill.name === "aweb-coordination");
  assert.equal(composedSkill?.source, "aweb.tasks");
});
