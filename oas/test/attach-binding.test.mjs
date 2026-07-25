import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";

const CAPABILITY_SOURCE = resolve(new URL("../capabilities/oas-aweb", import.meta.url).pathname);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oas-attach-")));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path, content, mode) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, mode === undefined ? undefined : { mode });
}

function oasCli() {
  const root = process.env.OAS_TEST_ROOT
    || execFileSync("oas", ["root"], { encoding: "utf8" }).trim();
  const cli = join(root, "bin", "oas.mjs");
  assert.equal(existsSync(cli), true, `real OAS CLI not found at ${cli}`);
  return cli;
}

function gitRepo(directory) {
  mkdirSync(directory, { recursive: true });
  execFileSync("git", ["init", "-q", directory]);
  execFileSync("git", ["-C", directory, "config", "user.email", "test@example.invalid"]);
  execFileSync("git", ["-C", directory, "config", "user.name", "Test"]);
  write(join(directory, ".gitignore"), "\n");
  execFileSync("git", ["-C", directory, "add", "."]);
  execFileSync("git", ["-C", directory, "commit", "-qm", "init"]);
}

function parseSuccess(result) {
  assert.equal(result.status, 0, result.stderr);
  const document = JSON.parse(result.stdout);
  if (document.schemaVersion === undefined) return document;
  assert.equal(document.schemaVersion, 1);
  assert.equal(document.ok, true, JSON.stringify(document.error));
  return document.result;
}

function fixture({ mode = "attach" } = {}) {
  const base = temporaryDirectory();
  const repo = join(base, "repo");
  gitRepo(repo);
  const agentsRoot = join(base, "agents");
  const soul = join(agentsRoot, "developer", "soul");
  write(join(soul, "soul.yaml"), `name: developer\nkind: persistent\nrepo: ${repo}\nwork: checkout\nruntime: pi\n`);
  write(join(soul, "AGENTS.md"), "# Developer\n");
  mkdirSync(join(agentsRoot, "developer", "instances"), { recursive: true });

  cpSync(CAPABILITY_SOURCE, join(repo, ".agents", "capabilities", "owned", "oas-aweb"), { recursive: true });
  write(join(repo, "oas-config.yaml"), `capabilities:\n  layers:\n    messaging:\n      capability: oas.aweb\n      global:\n        enabled: true\n        settings:\n          identity_binding:\n            schema_version: 1\n            mode: ${mode}\n            principal: throwaway\n`);
  write(join(repo, "oas", "agents", "developer", "principals", "throwaway.yaml"), [
    "schema_version: 1",
    "address: example.test/throwaway",
    "stable_id: did:aw:2ThrowawayStableId123",
    "team_id: test-team:example.test",
    "soul: developer",
    "soul_version: 1.2.3",
    "",
  ].join("\n"));

  const principalHome = join(base, "principal-store");
  const principal = join(principalHome, "test-team", "example.test", "2ThrowawayStableId123");
  const credentials = join(principal, "credentials");
  const state = join(principal, "state");
  write(join(credentials, "signing.key"), "principal-secret-that-must-never-enter-instance\n");
  write(join(state, "state.json"), "{\"durable\":true}\n");

  const bin = join(base, "bin");
  const awLog = join(base, "aw-argv.jsonl");
  write(join(bin, "pi"), "#!/bin/sh\nexit 0\n", 0o755);
  write(join(bin, "aw"), `#!/usr/bin/env node\nimport { appendFileSync } from "node:fs";\nappendFileSync(process.env.FAKE_AW_LOG, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }) + "\\n");\nconst argv = process.argv.slice(2);\nif (argv.includes("delete") || argv.includes("reset") || argv.includes("init") || argv.includes("invite") || argv.includes("join")) process.exit(93);\nif (argv.at(-2) === "whoami" && argv.at(-1) === "--json") {\n  process.stdout.write(JSON.stringify({ address: "example.test/throwaway", stable_id: "did:aw:2ThrowawayStableId123", team_id: "test-team:example.test" }) + "\\n");\n  process.exit(0);\n}\nprocess.exit(92);\n`, 0o755);

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    PI_AGENTS_ROOT: agentsRoot,
    AWEB_PRINCIPAL_HOME: principalHome,
    FAKE_AW_LOG: awLog,
    PI_AGENTS_TMUX_SESSION: "oas-attach-test-no-session",
  };
  return { base, repo, agentsRoot, principalHome, principal, credentials, state, awLog, env };
}

function allPaths(root) {
  const paths = [];
  function visit(path) {
    paths.push(path);
    if (lstatSync(path).isDirectory()) {
      for (const name of readdirSync(path)) visit(join(path, name));
    }
  }
  visit(root);
  return paths;
}

test("real OAS attach spawn persists external ownership and ordinary retire preserves the principal", () => {
  const f = fixture();
  const cli = oasCli();
  const spawn = spawnSync(process.execPath, [cli, "spawn", "developer", "--purpose", "attach-proof", "--no-launch", "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const spawned = parseSuccess(spawn);
  assert.deepEqual(spawned.warnings ?? [], []);

  const instanceMeta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  const binding = instanceMeta.capabilityMeta?.["oas.aweb"]?.identity_binding;
  assert.deepEqual(binding, {
    schema_version: 1,
    mode: "attach",
    cleanup_owner: "external",
    principal: "throwaway",
    declaration_path: join(f.repo, "oas", "agents", "developer", "principals", "throwaway.yaml"),
    address: "example.test/throwaway",
    stable_id: "did:aw:2ThrowawayStableId123",
    team_id: "test-team:example.test",
    soul: "developer",
    soul_version: "1.2.3",
    store: {
      home: f.principalHome,
      principal: f.principal,
      credentials: f.credentials,
      state: f.state,
    },
  });
  assert.match(readFileSync(join(spawned.home, "TASK.md"), "utf8"), /external cleanup ownership/);
  assert.equal(existsSync(join(spawned.home, ".aw")), false);
  const credentialStat = statSync(join(f.credentials, "signing.key"));
  for (const path of allPaths(spawned.home)) {
    assert.notEqual(basename(path), ".aw", `identity directory copied into instance at ${path}`);
    const entry = lstatSync(path);
    assert.equal(entry.isSymbolicLink() && realpathSync(path).startsWith(`${f.principal}${process.platform === "win32" ? "\\" : "/"}`), false, `principal symlink at ${path}`);
    if (entry.isFile()) {
      const instanceStat = statSync(path);
      assert.notDeepEqual([instanceStat.dev, instanceStat.ino], [credentialStat.dev, credentialStat.ino], `credential hardlink at ${path}`);
      assert.notEqual(readFileSync(path).includes("principal-secret-that-must-never-enter-instance"), true, `credential copy at ${path}`);
    }
  }

  const invocationsAtSpawn = readFileSync(f.awLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(invocationsAtSpawn, [{
    argv: ["--identity-home", f.credentials, "whoami", "--json"],
    cwd: spawned.home,
  }]);

  const retire = spawnSync(process.execPath, [cli, "retire", spawned.instance, "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const retired = parseSuccess(retire);
  assert.equal(existsSync(spawned.home), false);
  assert.deepEqual(retired.warnings ?? [], []);
  assert.deepEqual(retired.capabilityMeta?.["oas.aweb"], {
    identity_binding: binding,
    retirement: { action: "preserve_principal", cleanup_owner: "external" },
  });
  assert.equal(readFileSync(f.awLog, "utf8").trim().split("\n").length, 1, "retire must not invoke aw");
  assert.equal(readFileSync(join(f.credentials, "signing.key"), "utf8"), "principal-secret-that-must-never-enter-instance\n");
  assert.equal(readFileSync(join(f.state, "state.json"), "utf8"), "{\"durable\":true}\n");
});

test("real OAS attach fails visibly when aw reports a different stable identity", () => {
  const f = fixture();
  const awPath = join(f.base, "bin", "aw");
  writeFileSync(awPath, readFileSync(awPath, "utf8").replace(
    'stable_id: "did:aw:2ThrowawayStableId123"',
    'stable_id: "did:aw:2DifferentStableId456"',
  ));
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-mismatch", "--no-launch", "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /stable_id.*does not match declaration/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["oas.aweb"], undefined);
  assert.equal(existsSync(join(spawned.home, ".aw")), false);
});

test("real OAS attach rechecks credential symlinks before invoking aw", () => {
  const f = fixture();
  const target = join(f.base, "linked-credentials");
  mkdirSync(target);
  rmSync(f.credentials, { recursive: true });
  symlinkSync(target, f.credentials, "dir");
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-link", "--no-launch", "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /symbolic link/);
  assert.equal(existsSync(f.awLog), false, "unsafe credential path must fail before aw invocation");
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["oas.aweb"], undefined);
});

test("real OAS spawn rejects a non-attach binding without minting or cleanup authority", () => {
  const f = fixture({ mode: "provision" });
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-provision", "--no-launch", "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /only attach mode is supported/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["oas.aweb"], undefined);
  assert.equal(existsSync(f.awLog), false);
  assert.equal(existsSync(join(spawned.home, ".aw")), false);
  mkdirSync(join(spawned.home, ".aw"));

  const retire = spawnSync(process.execPath, [oasCli(), "retire", spawned.instance, "--json"], {
    cwd: f.repo,
    env: f.env,
    encoding: "utf8",
  });
  const retired = parseSuccess(retire);
  assert.equal(existsSync(spawned.home), false);
  assert.equal(retired.warnings.length, 1);
  assert.match(retired.warnings[0], /no principal cleanup was attempted/);
  assert.equal(retired.capabilityMeta?.["oas.aweb"], undefined);
  assert.equal(existsSync(f.awLog), false, "missing binding metadata must grant no cleanup authority");
});
