import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { afterEach, test } from "node:test";

import { cleanupCorroborationPayload } from "../.agents/capabilities/owned/aweb-identity-attach/lib/binding-policy.mjs";

const CAPABILITY_SOURCE = resolve(new URL("../.agents/capabilities/owned/aweb-identity-attach", import.meta.url).pathname);
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

function fixture({
  mode = "attach",
  schemaVersion = 1,
  mintingAuthority = mode === "provision-disposable" ? "throwaway" : undefined,
  mintingAuthorityPath = mode === "provision-disposable" ? "hosted" : undefined,
} = {}) {
  const base = temporaryDirectory();
  const repo = join(base, "repo");
  gitRepo(repo);
  const agentsRoot = join(base, "agents");
  const soul = join(agentsRoot, "developer", "soul");
  write(join(soul, "soul.yaml"), `name: developer\nkind: persistent\nrepo: ${repo}\nwork: checkout\nruntime: pi\n`);
  write(join(soul, "AGENTS.md"), "# Developer\n");
  mkdirSync(join(agentsRoot, "developer", "instances"), { recursive: true });

  const capability = join(repo, ".agents", "capabilities", "owned", "aweb-identity-attach");
  cpSync(CAPABILITY_SOURCE, capability, { recursive: true });
  const bindingSetting = mode === "attach" || mode === "attach-existing"
    ? `            principal: throwaway\n`
    : mintingAuthority == null
      ? ""
      : `            minting_authority: ${mintingAuthority}\n            minting_authority_path: ${mintingAuthorityPath}\n`;
  write(join(repo, "oas-config.yaml"), `capabilities:\n  layers:\n    messaging:\n      capability: aweb.identity-attach\n      global:\n        enabled: true\n        settings:\n          identity_binding:\n            schema_version: ${schemaVersion}\n            mode: ${mode}\n${bindingSetting}`);
  const declarationPath = join(repo, "oas", "agents", "developer", "principals", "throwaway.yaml");
  write(declarationPath, [
    "schema_version: 1",
    "address: example.test/throwaway",
    "stable_id: did:aw:2ThrowawayStableId123",
    "team_id: test-team:example.test",
    "soul: developer",
    "soul_version: 1.2.3",
    "",
  ].join("\n"));
  execFileSync("git", ["-C", repo, "add", "."]);
  execFileSync("git", ["-C", repo, "commit", "-qm", "configure identity capability"]);

  const principalHome = join(base, "principal-store");
  const principal = join(principalHome, "test-team", "example.test", "2ThrowawayStableId123");
  const credentials = join(principal, "credentials");
  const state = join(principal, "state");
  write(join(credentials, "signing.key"), "principal-secret-that-must-never-enter-instance\n");
  write(join(state, "state.json"), "{\"durable\":true}\n");

  const bin = join(base, "bin");
  const awLog = join(base, "aw-argv.jsonl");
  write(join(bin, "pi"), "#!/bin/sh\nexit 0\n", 0o755);
  write(join(bin, "aw"), `#!/usr/bin/env node\nimport { appendFileSync } from "node:fs";\nappendFileSync(process.env.FAKE_AW_LOG, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }) + "\\n");\nconst argv = process.argv.slice(2);\nif (argv.includes("delete") || argv.includes("reset") || argv.includes("init") || argv.includes("invite") || argv.includes("join")) process.exit(93);\nif (argv.at(-2) === "whoami" && argv.at(-1) === "--json") {\n  process.stdout.write(JSON.stringify({ address: "example.test/throwaway", stable_id: "did:aw:2ThrowawayStableId123" }) + "\\n");\n  process.exit(0);\n}\nif (argv.includes("team") && argv.includes("list") && argv.at(-1) === "--json") {\n  process.stdout.write(JSON.stringify({ active_team: "test-team:example.test", memberships: [{ team_id: "test-team:example.test", active: true }] }) + "\\n");\n  process.exit(0);\n}\nif (argv.includes("import-request") && argv.at(-1) === "--json") {\n  process.stdout.write(JSON.stringify({ controller_did: "did:key:z6MkiLocalController123" }) + "\\n");\n  process.exit(0);\n}\nprocess.exit(92);\n`, 0o755);

  const corroborationHome = join(principalHome, ".corroboration", "cleanup");
  mkdirSync(corroborationHome, { recursive: true });
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    PI_AGENTS_ROOT: agentsRoot,
    AWEB_PRINCIPAL_HOME: principalHome,
    FAKE_AW_LOG: awLog,
    PI_AGENTS_TMUX_SESSION: "oas-attach-test-no-session",
  };
  return { base, repo, agentsRoot, capability, declarationPath, principalHome, principal, credentials, state, corroborationHome, awLog, awPath: join(bin, "aw"), env };
}

function digestedCleanupCorroboration(instanceID, receipt) {
  const record = { schema_version: 1, corroboration_class: "local-same-uid", instance_id: instanceID, receipt };
  return {
    ...record,
    digest: createHash("sha256").update(cleanupCorroborationPayload(record)).digest("hex"),
  };
}

function writeCleanupCorroboration(f, instanceID, receipt) {
  const record = digestedCleanupCorroboration(instanceID, receipt);
  write(join(f.corroborationHome, `${instanceID}.json`), `${JSON.stringify(record, null, 2)}\n`);
}

function pathIsWithinOrEqual(root, candidate) {
  const fromRoot = relative(root, candidate);
  return fromRoot === "" || (fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot));
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

function assertNoInstanceIdentityMaterial(instanceHome, principal, credentialFile) {
  assert.equal(existsSync(join(instanceHome, ".aw")), false);
  const credentialStat = statSync(credentialFile);
  const secret = readFileSync(credentialFile, "utf8").trim();
  for (const path of allPaths(instanceHome)) {
    assert.notEqual(basename(path), ".aw", `identity directory copied into instance at ${path}`);
    const entry = lstatSync(path);
    assert.equal(entry.isSymbolicLink() && pathIsWithinOrEqual(principal, realpathSync(path)), false, `principal symlink at ${path}`);
    if (entry.isFile()) {
      const instanceStat = statSync(path);
      assert.notDeepEqual([instanceStat.dev, instanceStat.ino], [credentialStat.dev, credentialStat.ino], `credential hardlink at ${path}`);
      assert.notEqual(secret && readFileSync(path).includes(secret), true, `credential copy at ${path}`);
    }
  }
}

test("attach capability identity is explicit and cannot collide with upstream destructive oas.aweb", () => {
  const manifest = JSON.parse(readFileSync(join(CAPABILITY_SOURCE, "oas.json"), "utf8"));
  assert.equal(manifest.capability, "aweb.identity-attach");
  assert.notEqual(manifest.capability, "oas.aweb");
  assert.equal(manifest.layer, "messaging");
});

test("instance link containment includes an exact renamed link to the principal root", () => {
  const root = temporaryDirectory();
  const principal = join(root, "principal");
  const instance = join(root, "instance");
  const credential = join(principal, "credentials", "signing.key");
  write(credential, "exact-principal-link-secret\n");
  mkdirSync(instance);
  const renamedLink = join(instance, "ordinary-looking-directory");
  symlinkSync(principal, renamedLink, "dir");
  assert.equal(pathIsWithinOrEqual(principal, realpathSync(renamedLink)), true);
  assert.equal(pathIsWithinOrEqual(principal, join(principal, "credentials")), true);
  assert.equal(pathIsWithinOrEqual(principal, join(root, "principal-sibling")), false);
  assert.throws(
    () => assertNoInstanceIdentityMaterial(instance, principal, credential),
    /principal symlink/,
  );
});

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
  const binding = instanceMeta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding;
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
  assertNoInstanceIdentityMaterial(spawned.home, f.principal, join(f.credentials, "signing.key"));

  const invocationsAtSpawn = readFileSync(f.awLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(invocationsAtSpawn, [{
    argv: ["--identity-home", f.credentials, "whoami", "--json"],
    cwd: spawned.home,
  }, {
    argv: ["--identity-home", f.credentials, "id", "team", "list", "--json"],
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
  assert.deepEqual(retired.capabilityMeta?.["aweb.identity-attach"], {
    identity_binding: binding,
    retirement: { action: "preserve_principal", cleanup_owner: "external" },
  });
  assert.equal(readFileSync(f.awLog, "utf8").trim().split("\n").length, 2, "retire must not invoke aw");
  assert.equal(readFileSync(join(f.credentials, "signing.key"), "utf8"), "principal-secret-that-must-never-enter-instance\n");
  assert.equal(readFileSync(join(f.state, "state.json"), "utf8"), "{\"durable\":true}\n");
});

test("real OAS attach-existing v2 emits an externally owned bound receipt", () => {
  const f = fixture({ mode: "attach-existing", schemaVersion: 2 });
  const spawn = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "attach-v2", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  });
  const spawned = parseSuccess(spawn);
  assert.deepEqual(spawned.warnings ?? [], []);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  const receipt = meta.capabilityMeta["aweb.identity-attach"].identity_binding;
  assert.equal(receipt.schema_version, 2);
  assert.equal(receipt.mode, "attach-existing");
  assert.equal(receipt.lifecycle, "bound");
  assert.equal(receipt.cleanup_owner, "external");
  assert.equal(receipt.resource_identity.kind, "declared-principal");
  assert.equal(receipt.resource_identity.stable_id, "did:aw:2ThrowawayStableId123");
  assert.equal(receipt.resource_identity.reference, f.declarationPath);
});

for (const [mode, cleanupOwner] of [
  ["provision-disposable", "instance"],
]) {
  test(`real OAS ${mode} emits a pending non-authorizing receipt without provisioning`, () => {
    const f = fixture({ mode, schemaVersion: 2 });
    const spawn = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", mode, "--no-launch", "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    });
    const spawned = parseSuccess(spawn);
    assert.equal(spawned.warnings.length, 1);
    assert.match(spawned.warnings[0], /provisioning execution is not installed/);
    const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
    const receipt = meta.capabilityMeta["aweb.identity-attach"].identity_binding;
    const operationID = receipt.journal_operation;
    assert.match(operationID, /^oas-[A-Za-z0-9_-]{21}[AQgw]$/);
    assert.ok(operationID.length <= 64);
    assert.deepEqual(receipt, {
      schema_version: 2,
      mode,
      lifecycle: "provision-pending",
      cleanup_owner: cleanupOwner,
      resource_identity: {
        kind: "provision-operation",
        operation_id: operationID,
        stable_id: null,
        reference: `operation:${operationID}`,
        cleanup_authority: null,
      },
      journal_operation: operationID,
    });
    assert.deepEqual(meta.capabilityMeta["aweb.identity-attach"].minting_authority, {
      schema_version: 2,
      path: "hosted",
      authority_class: "hosted-creator-agent",
      creator: {
        principal: "throwaway",
        declaration_path: f.declarationPath,
        address: "example.test/throwaway",
        stable_id: "did:aw:2ThrowawayStableId123",
        team_id: "test-team:example.test",
      },
      grant_listing_scope: "creator-agent-only",
      grant_retirement_rule: "grants_terminal_before_creator_retirement",
      known_id_recovery: "admin-revoke",
      unreceived_id_residual: "server-expiry-bounded-self-terminating",
      default_expiry_hours: 24,
      maximum_expiry_days: 30,
      rule_enforcement: "declarative_no_universal_retirement_choke_point",
    });
    const authorityCalls = readFileSync(f.awLog, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(authorityCalls, [{
      argv: ["--identity-home", f.credentials, "whoami", "--json"],
      cwd: spawned.home,
    }, {
      argv: ["--identity-home", f.credentials, "id", "team", "list", "--json"],
      cwd: spawned.home,
    }]);
    assert.equal(existsSync(join(spawned.home, ".aw")), false, "disposable instance credentials must not become minting authority");

    const retire = spawnSync(process.execPath, [oasCli(), "retire", spawned.instance, "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    });
    const retired = parseSuccess(retire);
    assert.equal(retired.capabilityMeta["aweb.identity-attach"].retirement.cleanup_authorized, false);
    assert.equal(retired.capabilityMeta["aweb.identity-attach"].retirement.action, "preserve");
  });
}

test("real OAS emits a local-controller authority statement with indefinite grant semantics", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2, mintingAuthorityPath: "local-controller" });
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "local-authority", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.deepEqual(meta.capabilityMeta["aweb.identity-attach"].minting_authority, {
    schema_version: 2,
    path: "local-controller",
    authority_class: "machine-wide-awid-team-controller-key",
    intended_creator: {
      principal: "throwaway",
      declaration_path: f.declarationPath,
      address: "example.test/throwaway",
      stable_id: "did:aw:2ThrowawayStableId123",
      team_id: "test-team:example.test",
    },
    controller_did: "did:key:z6MkiLocalController123",
    authority_scope: "machine-wide-same-uid",
    grant_enumeration: "known-location-files",
    grant_lifetime: "indefinite-no-expiry-or-use-counter",
    creator_loss_effect: "grants-remain-enumerable",
    grant_cleanup_rule: "enumerate-and-remove-abandoned-grants",
    rule_enforcement: "declarative_no_universal_retirement_choke_point",
  });
  const authorityCalls = readFileSync(f.awLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(authorityCalls, [{
    argv: ["--identity-home", f.credentials, "whoami", "--json"],
    cwd: spawned.home,
  }, {
    argv: ["--identity-home", f.credentials, "id", "team", "list", "--json"],
    cwd: spawned.home,
  }, {
    argv: [
      "id", "team", "import-request",
      "--team", "test-team",
      "--namespace", "example.test",
      "--timestamp", "2000-01-01T00:00:00Z",
      "--json",
    ],
    cwd: spawned.home,
  }]);
});

test("real OAS refuses declared local-controller path without controller authority", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2, mintingAuthorityPath: "local-controller" });
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8").replace(
    'controller_did: "did:key:z6MkiLocalController123"',
    'controller_did: "missing"',
  ));
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "local-authority-missing", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /did not return a valid controller_did/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
});

test("real OAS refuses provision-durable before ephemeral authority resolution", () => {
  const f = fixture({ mode: "provision-durable", schemaVersion: 2 });
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "durable-refused", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /provision-durable.*not executable/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
  assert.equal(existsSync(f.awLog), false, "durable refusal must precede ephemeral authority resolution");
});

test("real OAS provision-disposable rejects missing declared minting authority", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2, mintingAuthority: null });
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "authority-missing", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /minting_authority/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
  assert.equal(existsSync(f.awLog), false);
});

test("real OAS provision-disposable rejects an uncommitted minting authority declaration", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
  writeFileSync(f.declarationPath, `${readFileSync(f.declarationPath, "utf8")}# unreviewed authority change\n`);
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "authority-uncommitted", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /minting authority declaration must be committed and unmodified/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
  assert.equal(existsSync(f.awLog), false);
});

test("real OAS provision-disposable rejects minting credentials that disagree with the declaration", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8").replace(
    'stable_id: "did:aw:2ThrowawayStableId123"',
    'stable_id: "did:aw:2DifferentStableId456"',
  ));
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "authority-mismatch", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /stable_id.*does not match declaration/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
  const calls = readFileSync(f.awLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(calls, [{
    argv: ["--identity-home", f.credentials, "whoami", "--json"],
    cwd: spawned.home,
  }]);
});

test("distinct production intents receive opaque carrier-safe operation identities", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
  const receipts = [];
  const instances = [];
  for (const purpose of ["distinct-one", "distinct-two", "x".repeat(80)]) {
    const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", purpose, "--no-launch", "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    }));
    instances.push(spawned.instance);
    const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
    receipts.push(meta.capabilityMeta["aweb.identity-attach"].identity_binding);
  }
  assert.equal(new Set(instances).size, instances.length);
  const operationIDs = receipts.map((receipt) => receipt.journal_operation);
  assert.equal(new Set(operationIDs).size, operationIDs.length);
  for (const operationID of operationIDs) {
    assert.match(operationID, /^oas-[A-Za-z0-9_-]{21}[AQgw]$/);
    assert.ok(operationID.length <= 64);
  }
});

test("local same-UID corroboration guards cleanup judgement against receipt-only mistakes", () => {
  function spawnedDisposable() {
    const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
    const spawn = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "cleanup-judgement", "--no-launch", "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    });
    const spawned = parseSuccess(spawn);
    const metaPath = join(spawned.home, "instance.json");
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    const receipt = meta.capabilityMeta["aweb.identity-attach"].identity_binding;
    receipt.lifecycle = "provisioned";
    receipt.resource_identity.cleanup_authority = "local-controller";
    writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`);
    return { f, spawned, receipt };
  }

  const forged = spawnedDisposable();
  const forgedRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", forged.spawned.instance, "--json"], {
    cwd: forged.f.repo, env: forged.f.env, encoding: "utf8",
  }));
  assert.deepEqual(forgedRetire.capabilityMeta["aweb.identity-attach"].retirement, {
    action: "preserve",
    cleanup_authorized: false,
    reason: "cleanup_corroboration_missing_or_mismatched",
  });

  const substituted = spawnedDisposable();
  const otherReceipt = {
    ...substituted.receipt,
    resource_identity: {
      ...substituted.receipt.resource_identity,
      operation_id: "victim-operation",
      reference: "operation:victim-operation",
    },
    journal_operation: "victim-operation",
  };
  writeCleanupCorroboration(substituted.f, substituted.spawned.instance, otherReceipt);
  const substitutedRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", substituted.spawned.instance, "--json"], {
    cwd: substituted.f.repo, env: substituted.f.env, encoding: "utf8",
  }));
  assert.deepEqual(substitutedRetire.capabilityMeta["aweb.identity-attach"].retirement, {
    action: "preserve",
    cleanup_authorized: false,
    reason: "cleanup_corroboration_missing_or_mismatched",
  });

  const invalidDigest = spawnedDisposable();
  writeCleanupCorroboration(invalidDigest.f, invalidDigest.spawned.instance, invalidDigest.receipt);
  const invalidDigestPath = join(invalidDigest.f.corroborationHome, `${invalidDigest.spawned.instance}.json`);
  const invalidDigestRecord = JSON.parse(readFileSync(invalidDigestPath, "utf8"));
  invalidDigestRecord.digest = "0".repeat(64);
  writeFileSync(invalidDigestPath, `${JSON.stringify(invalidDigestRecord, null, 2)}\n`);
  const invalidDigestRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", invalidDigest.spawned.instance, "--json"], {
    cwd: invalidDigest.f.repo, env: invalidDigest.f.env, encoding: "utf8",
  }));
  assert.equal(invalidDigestRetire.capabilityMeta["aweb.identity-attach"].retirement.cleanup_authorized, false);

  const linked = spawnedDisposable();
  const linkedTarget = join(linked.f.base, "untrusted-corroboration.json");
  write(linkedTarget, `${JSON.stringify(digestedCleanupCorroboration(linked.spawned.instance, linked.receipt), null, 2)}\n`);
  symlinkSync(linkedTarget, join(linked.f.corroborationHome, `${linked.spawned.instance}.json`));
  const linkedRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", linked.spawned.instance, "--json"], {
    cwd: linked.f.repo, env: linked.f.env, encoding: "utf8",
  }));
  assert.equal(linkedRetire.capabilityMeta["aweb.identity-attach"].retirement.cleanup_authorized, false);

  const remoteRequired = spawnedDisposable();
  remoteRequired.receipt.resource_identity.cleanup_authority = "remote-authority";
  const remoteMetaPath = join(remoteRequired.spawned.home, "instance.json");
  const remoteMeta = JSON.parse(readFileSync(remoteMetaPath, "utf8"));
  remoteMeta.capabilityMeta["aweb.identity-attach"].identity_binding = remoteRequired.receipt;
  writeFileSync(remoteMetaPath, `${JSON.stringify(remoteMeta, null, 2)}\n`);
  writeCleanupCorroboration(remoteRequired.f, remoteRequired.spawned.instance, remoteRequired.receipt);
  const remoteRequiredRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", remoteRequired.spawned.instance, "--json"], {
    cwd: remoteRequired.f.repo, env: remoteRequired.f.env, encoding: "utf8",
  }));
  assert.deepEqual(remoteRequiredRetire.capabilityMeta["aweb.identity-attach"].retirement, {
    action: "preserve",
    cleanup_authorized: false,
    reason: "required_remote_authority_corroboration_unavailable",
  });

  const owned = spawnedDisposable();
  writeCleanupCorroboration(owned.f, owned.spawned.instance, owned.receipt);
  const ownedRetire = parseSuccess(spawnSync(process.execPath, [oasCli(), "retire", owned.spawned.instance, "--json"], {
    cwd: owned.f.repo, env: owned.f.env, encoding: "utf8",
  }));
  assert.deepEqual(ownedRetire.capabilityMeta["aweb.identity-attach"].retirement, {
    action: "authorize_cleanup",
    cleanup_authorized: true,
    reason: "corroborating_local_record_matches_disposable_resource",
    authority_scope: "local_same_uid_accident_guard",
  });
  const ownedCalls = readFileSync(owned.f.awLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(ownedCalls, [{
    argv: ["--identity-home", owned.f.credentials, "whoami", "--json"],
    cwd: owned.spawned.home,
  }, {
    argv: ["--identity-home", owned.f.credentials, "id", "team", "list", "--json"],
    cwd: owned.spawned.home,
  }], "authorization judgement must not execute deletion");
});

test("real OAS attach rejects a declaration for a different soul before invoking aw", () => {
  const f = fixture();
  writeFileSync(f.declarationPath, readFileSync(f.declarationPath, "utf8").replace("soul: developer", "soul: reviewer"));
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-soul", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /declaration soul.*does not match OAS_AGENT/);
  assert.equal(existsSync(f.awLog), false);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
});

test("real OAS attach fails visibly when aw reports a different address", () => {
  const f = fixture();
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8").replace(
    'address: "example.test/throwaway"',
    'address: "example.test/impostor"',
  ));
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-address", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /address.*does not match declaration/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
});

test("real OAS attach fails visibly when aw reports a different stable identity", () => {
  const f = fixture();
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8").replace(
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
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
  assert.equal(existsSync(join(spawned.home, ".aw")), false);
});

test("real OAS provision-disposable rejects missing active-team evidence", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8")
    .replace('active_team: "test-team:example.test"', 'active_team: ""')
    .replace('memberships: [{ team_id: "test-team:example.test", active: true }]', 'memberships: []'));
  const spawned = parseSuccess(spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "authority-team-missing", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  }));
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /active team does not match declaration/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"]?.identity_binding, undefined);
});

test("real OAS provision-disposable rejects a complete authority active in another team", () => {
  const f = fixture({ mode: "provision-disposable", schemaVersion: 2 });
  writeFileSync(f.awPath, readFileSync(f.awPath, "utf8")
    .replace('active_team: "test-team:example.test"', 'active_team: "other-team:example.test"')
    .replace('team_id: "test-team:example.test"', 'team_id: "other-team:example.test"'));
  const result = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", "reject-team", "--no-launch", "--json"], {
    cwd: f.repo, env: f.env, encoding: "utf8",
  });
  const spawned = parseSuccess(result);
  assert.equal(spawned.warnings.length, 1);
  assert.match(spawned.warnings[0], /active team does not match declaration/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
});

test("real OAS attach reaches the point-of-use credential symlink recheck", () => {
  const f = fixture();
  const resolver = join(f.capability, "lib", "principals.mjs");
  const resolverSource = readFileSync(resolver, "utf8");
  const resolverGuard = "  assertPrincipalStoreSafe({ home, principal, credentials, state });\n\n  return { home, principal, credentials, state };";
  assert.equal(resolverSource.includes(resolverGuard), true);
  writeFileSync(resolver, resolverSource.replace(
    resolverGuard,
    "  return { home, principal, credentials, state };",
  ));
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
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
});

for (const malformed of [
  { name: "partial binding", change: () => ({ schema_version: 1, mode: "attach", cleanup_owner: "external" }) },
  { name: "wrong schema", change: (binding) => ({ ...binding, schema_version: 2 }) },
  { name: "wrong mode", change: (binding) => ({ ...binding, mode: "provision" }) },
  { name: "wrong cleanup owner", change: (binding) => ({ ...binding, cleanup_owner: "instance" }) },
  { name: "unknown binding field", change: (binding) => ({ ...binding, unexpected: "authority" }) },
  { name: "unknown store field", change: (binding) => ({ ...binding, store: { ...binding.store, unexpected: "/tmp" } }) },
  { name: "invalid public declaration value", change: (binding) => ({ ...binding, address: "not-an-address" }) },
  {
    name: "noncanonical declaration path",
    change: (binding) => ({
      ...binding,
      declaration_path: binding.declaration_path.replace(`${sep}oas${sep}`, `${sep}discarded${sep}..${sep}oas${sep}`),
    }),
  },
  {
    name: "wrong declaration suffix",
    change: (binding) => ({ ...binding, declaration_path: join(dirname(binding.declaration_path), "another.yaml") }),
  },
  {
    name: "noncanonical store path",
    change: (binding) => ({ ...binding, store: { ...binding.store, home: `${binding.store.home}${sep}discarded${sep}..` } }),
  },
  {
    name: "wrong structural store derivation",
    change: (binding) => ({ ...binding, store: { ...binding.store, credentials: join(binding.store.principal, "other-credentials") } }),
  },
]) {
  test(`ordinary OAS retire grants no receipt to ${malformed.name}`, () => {
    const f = fixture();
    const spawn = spawnSync(process.execPath, [oasCli(), "spawn", "developer", "--purpose", `retire-${malformed.name.replaceAll(" ", "-")}`, "--no-launch", "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    });
    const spawned = parseSuccess(spawn);
    assert.deepEqual(spawned.warnings ?? [], []);
    const metaPath = join(spawned.home, "instance.json");
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    const capabilityMeta = meta.capabilityMeta["aweb.identity-attach"];
    capabilityMeta.identity_binding = malformed.change(capabilityMeta.identity_binding);
    writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`);
    mkdirSync(join(spawned.home, ".aw"));

    const retire = spawnSync(process.execPath, [oasCli(), "retire", spawned.instance, "--json"], {
      cwd: f.repo, env: f.env, encoding: "utf8",
    });
    const retired = parseSuccess(retire);
    assert.deepEqual(retired.warnings ?? [], []);
    const decision = retired.capabilityMeta["aweb.identity-attach"];
    assert.equal(decision.retirement.action, "preserve");
    assert.equal(decision.retirement.cleanup_authorized, false);
    assert.equal(decision.retirement.reason, "missing_or_invalid_instance_receipt");
    assert.deepEqual(decision.identity_binding_evidence, capabilityMeta.identity_binding, "rejection must preserve malformed evidence");
    assert.equal(readFileSync(f.awLog, "utf8").trim().split("\n").length, 2, "retire must not invoke aw");
  });
}

test("production retire entry preserves on unparseable instance metadata", () => {
  const f = fixture();
  const result = spawnSync(process.execPath, [join(f.capability, "bin", "aweb-identity-attach.mjs"), "retire"], {
    cwd: f.repo,
    env: { ...f.env, OAS_EVENT: "retire", OAS_INSTANCE: "unparseable-1", OAS_META: "{" },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    meta: {
      identity_binding_evidence: {
        format: "unparseable",
        sha256: createHash("sha256").update("{").digest("hex"),
      },
      retirement: {
        action: "preserve",
        cleanup_authorized: false,
        reason: "unparseable_instance_metadata",
      },
    },
  });
  assert.equal(existsSync(f.awLog), false);
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
  assert.match(spawned.warnings[0], /legacy identity_binding v1 must declare mode attach/);
  const meta = JSON.parse(readFileSync(join(spawned.home, "instance.json"), "utf8"));
  assert.equal(meta.capabilityMeta?.["aweb.identity-attach"], undefined);
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
  assert.deepEqual(retired.warnings ?? [], []);
  assert.deepEqual(retired.capabilityMeta["aweb.identity-attach"].retirement, {
    action: "preserve",
    cleanup_authorized: false,
    reason: "missing_or_invalid_instance_receipt",
  });
  assert.equal(existsSync(f.awLog), false, "missing binding metadata must grant no cleanup authority");
});
