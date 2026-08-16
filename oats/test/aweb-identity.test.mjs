import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";

const HOOK = resolve(new URL("../.agents/capabilities/owned/aweb-identity/bin/aweb-identity.mjs", import.meta.url).pathname);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "aweb-identity-")));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/** A fake `aw` that records its argv+env and answers mint/revoke. */
function fakeAw(binDir, { mintExit = 0, revokeExit = 0, mintStdout } = {}) {
  const log = join(binDir, "aw-calls.jsonl");
  const script = `#!/usr/bin/env node
import { appendFileSync, mkdirSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, cwd: process.cwd(), identityHome: process.env.AWEB_IDENTITY_HOME }) + "\\n");
if (args[0] === "--version") process.exit(0);
if (args.slice(0, 3).join(" ") === "id grant mint") {
  const out = args[args.indexOf("--out") + 1];
  if (${mintExit} !== 0) { console.error("mint refused"); process.exit(${mintExit}); }
  mkdirSync(out, { recursive: true });
  console.log(${JSON.stringify(mintStdout ?? "")} || JSON.stringify({ grant_id: "g-123", expires_at: "2026-08-12T20:00:00Z", team_id: "aweb-oats:aweb.ai", alias: "coord", address: "aweb.ai/coord", out }));
  process.exit(0);
}
if (args.slice(0, 3).join(" ") === "id grant revoke") {
  if (${revokeExit} !== 0) { console.error("revoke refused"); process.exit(${revokeExit}); }
  console.log(JSON.stringify({ grant_id: args[3], status: "revoked" }));
  process.exit(0);
}
console.error("unexpected aw invocation: " + args.join(" "));
process.exit(9);
`;
  const awPath = join(binDir, "aw");
  write(awPath, script);
  chmodSync(awPath, 0o755);
  return { log };
}

function runHook(event, { env = {}, awOptions = {} } = {}) {
  const root = temporaryDirectory();
  const custody = join(root, "workspace");
  write(join(custody, ".aw", "identity.yaml"), "did: did:aw:test\n");
  const home = join(root, "instance-home");
  mkdirSync(home, { recursive: true });
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  const { log } = fakeAw(bin, awOptions);
  const result = spawnSync(process.execPath, [HOOK, event], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      OATS_WORKSPACE: custody,
      OATS_INSTANCE_HOME: home,
      OATS_HOME: home,
      OATS_INSTANCE: "coord-1",
      OATS_SETTINGS: JSON.stringify({}),
      OATS_META: "{}",
      ...env,
    },
  });
  const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { result, calls, custody, home };
}

function lastJson(stdout) {
  const line = String(stdout).trim().split("\n").filter(Boolean).pop() || "{}";
  return JSON.parse(line);
}

test("spawn mints a grant into the instance home and contributes the locator", () => {
  const { result, calls, custody, home } = runHook("spawn");
  assert.equal(result.status, 0, result.stderr);
  const out = lastJson(result.stdout);
  assert.equal(out.env.AWEB_IDENTITY_HOME, join(home, ".aweb-identity"));
  assert.equal(out.meta.grant_id, "g-123");
  assert.match(out.brief, /aweb\.ai\/coord/);
  assert.match(out.brief, /expires 2026-08-12T20:00:00Z/);
  const mint = calls.find((c) => c.args[2] === "mint");
  assert.ok(mint, "aw id grant mint was called");
  assert.equal(mint.cwd, custody);
  assert.equal(mint.identityHome, join(custody, ".aw"), "mint must run against the custody home, not an inherited grant home");
  assert.equal(mint.args[mint.args.indexOf("--label") + 1], "oats:coord-1");
  assert.equal(mint.args[mint.args.indexOf("--ttl") + 1], "8h");
  assert.equal(mint.args[mint.args.indexOf("--scope") + 1], "mail.read,mail.send,chat.read,chat.send");
});

test("spawn honors scopes, ttl, and custody-root settings", () => {
  const { result, calls, custody } = runHook("spawn", {
    env: { OATS_SETTINGS: JSON.stringify({ "custody-root": ".", scopes: ["mail.send"], ttl: "30m" }) },
  });
  assert.equal(result.status, 0, result.stderr);
  const mint = calls.find((c) => c.args[2] === "mint");
  assert.equal(mint.cwd, custody);
  assert.equal(mint.args[mint.args.indexOf("--scope") + 1], "mail.send");
  assert.equal(mint.args[mint.args.indexOf("--ttl") + 1], "30m");
});

test("spawn fails when the custody home is missing", () => {
  const root = temporaryDirectory();
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  fakeAw(bin);
  const home = join(root, "home");
  mkdirSync(home, { recursive: true });
  const result = spawnSync(process.execPath, [HOOK, "spawn"], {
    encoding: "utf8",
    env: {
      ...process.env, PATH: `${bin}:${process.env.PATH}`,
      OATS_WORKSPACE: join(root, "nowhere"), OATS_INSTANCE_HOME: home, OATS_HOME: home,
      OATS_INSTANCE: "coord-1", OATS_SETTINGS: "{}",
    },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not an initialized identity home/);
});

test("spawn fails when mint fails or returns no grant", () => {
  const failed = runHook("spawn", { awOptions: { mintExit: 3 } });
  assert.notEqual(failed.result.status, 0);
  assert.match(failed.result.stderr, /no grant was minted/);
  const garbage = runHook("spawn", { awOptions: { mintStdout: "not json" } });
  assert.notEqual(garbage.result.status, 0);
  assert.match(garbage.result.stderr, /no usable grant/);
});

test("spawn refuses to overwrite an existing credential directory", () => {
  const root = temporaryDirectory();
  const custody = join(root, "ws");
  write(join(custody, ".aw", "identity.yaml"), "did: did:aw:test\n");
  const home = join(root, "home");
  mkdirSync(join(home, ".aweb-identity"), { recursive: true });
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  fakeAw(bin);
  const result = spawnSync(process.execPath, [HOOK, "spawn"], {
    encoding: "utf8",
    env: {
      ...process.env, PATH: `${bin}:${process.env.PATH}`,
      OATS_WORKSPACE: custody, OATS_INSTANCE_HOME: home, OATS_HOME: home,
      OATS_INSTANCE: "coord-1", OATS_SETTINGS: "{}",
    },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /refusing to overwrite/);
});

test("retire revokes the recorded grant from the custody home", () => {
  const { result, calls, custody } = runHook("retire", { env: { OATS_META: JSON.stringify({ grant_id: "g-123" }) } });
  assert.equal(result.status, 0, result.stderr);
  const revoke = calls.find((c) => c.args[2] === "revoke");
  assert.ok(revoke, "aw id grant revoke was called");
  assert.equal(revoke.args[3], "g-123");
  assert.equal(revoke.cwd, custody);
});

test("retire with no recorded grant is a warning, not a failure", () => {
  const { result, calls } = runHook("retire");
  assert.equal(result.status, 0, result.stderr);
  assert.equal(calls.filter((c) => c.args[2] === "revoke").length, 0);
  assert.match(lastJson(result.stdout).warning, /nothing to revoke/);
});

test("retire fails loudly when revoke fails, naming the TTL backstop", () => {
  const { result } = runHook("retire", {
    env: { OATS_META: JSON.stringify({ grant_id: "g-123" }) },
    awOptions: { revokeExit: 4 },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /still expires at its TTL/);
});
