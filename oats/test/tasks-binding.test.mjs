import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";
import { oatsCliPath } from "./helpers/oats-test-root.mjs";

const CAPABILITY_SOURCE = resolve(new URL("../.agents/capabilities/owned/aweb-tasks", import.meta.url).pathname);
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
  const instance = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  for (const name of ["aweb-coordination", "aweb-tasks"]) {
    assert.equal(existsSync(join(spawned.home, ".agents", "skills", name, "SKILL.md")), true);
    const composedSkill = instance.skills.find((skill) => skill.name === name);
    assert.equal(composedSkill?.source, "aweb.tasks");
  }
});
