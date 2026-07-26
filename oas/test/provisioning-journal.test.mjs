import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";

import {
  createProvisionIntent,
  listRecoverableProvisionIntents,
  loadProvisionIntent,
  markProvisionIntentAbandoned,
  markProvisionIntentCleanupPending,
  markProvisionIntentComplete,
  markProvisionIntentQuarantined,
  retryProvisionIntentQuarantine,
  markProvisionIntentHandedOff,
  markProvisionIntentPrepared,
  markProvisionIntentProvisioning,
  withProvisionIntentLock,
  writeProvisionCleanupCorroboration,
} from "../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-journal.mjs";
import { loadCleanupCorroboration } from "../.agents/capabilities/owned/aweb-identity-attach/lib/binding-policy.mjs";

const OPERATION_A = "oas-AAAAAAAAAAAAAAAAAAAAAA";
const OPERATION_B = "oas-BBBBBBBBBBBBBBBBBBBBBQ";
const operationAlias = (operation) => `oas-${createHash("sha256").update(operation).digest("hex").slice(0, 32)}`;
const AUTHORITY = Object.freeze({
  schema_version: 2,
  path: "local-controller",
  authority_class: "machine-wide-awid-team-controller-key",
  intended_creator: {
    principal: "provisioner",
    declaration_path: "/repo/oas/agents/developer/principals/provisioner.yaml",
    address: "acme.test/provisioner",
    stable_id: "did:aw:Provisioner",
    team_id: "backend:acme.test",
  },
  controller_did: "did:key:z6MkiController",
  authority_scope: "machine-wide-same-uid",
  grant_enumeration: "known-location-files",
  grant_lifetime: "indefinite-no-expiry-or-use-counter",
  creator_loss_effect: "grants-remain-enumerable",
  grant_cleanup_rule: "enumerate-and-remove-abandoned-grants",
  rule_enforcement: "declarative_no_universal_retirement_choke_point",
});

function tempRoot(t, prefix) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("provision intent is durable before side effects and contains no bearer secret", (t) => {
  const root = tempRoot(t, "aweb-provision-journal-");

  const intent = createProvisionIntent(root, {
    operationID: OPERATION_A,
    instanceID: "developer-one",
    teamID: "backend:acme.test",
    authority: AUTHORITY,
    authorityHome: join(root, "authority"),
    now: new Date("2026-07-26T00:00:00Z"),
  });
  assert.equal(intent.state, "allocated");
  assert.equal(intent.alias, operationAlias(OPERATION_A));
  assert.equal(intent.identity_home, join(root, ".provisioning", "identities", OPERATION_A));
  assert.equal(intent.authority.controller_did, AUTHORITY.controller_did);
  assert.equal(statSync(join(root, ".provisioning", "intents", `${OPERATION_A}.json`)).mode & 0o777, 0o600);
  assert.doesNotMatch(readFileSync(join(root, ".provisioning", "intents", `${OPERATION_A}.json`), "utf8"), /token|secret/i);
  assert.deepEqual(loadProvisionIntent(root, OPERATION_A), intent);
  assert.throws(() => createProvisionIntent(root, {
    operationID: OPERATION_A,
    instanceID: "different-instance",
    teamID: "backend:acme.test",
    authority: AUTHORITY,
    authorityHome: join(root, "authority"),
    now: new Date("2026-07-26T00:00:01Z"),
  }), /already belongs to instance/);
});

test("scanner owns stale incomplete work but never infers that prepared means launched", (t) => {
  const root = tempRoot(t, "aweb-provision-scan-");
  const start = new Date("2026-07-26T00:00:00Z");
  createProvisionIntent(root, { operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY, authorityHome: join(root, "authority"), now: start });
  createProvisionIntent(root, { operationID: OPERATION_B, instanceID: "instance-b", teamID: "backend:acme.test", authority: AUTHORITY, authorityHome: join(root, "authority"), now: start });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  markProvisionIntentProvisioning(root, OPERATION_B, start);
  markProvisionIntentPrepared(root, OPERATION_B, {
    status: "provisioned",
    operation_id: OPERATION_B,
    team_id: "backend:acme.test",
    alias: operationAlias(OPERATION_B),
    identity_home: join(root, ".provisioning", "identities", OPERATION_B),
    did_key: "did:key:z6MkiWorker",
    certificate_id: "certificate-b",
    agent_id: "agent-b",
    workspace_id: "workspace-b",
    registry_url: "https://registry.test",
    aweb_url: "https://aweb.test",
  }, start);

  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:29Z"), staleAfterMs: 30_000,
  }), [], "fresh no-op has a stale positive control below");
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:31Z"), staleAfterMs: 30_000,
  }).map((intent) => intent.operation_id), [OPERATION_A]);
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:31Z"), staleAfterMs: 30_000,
  }).map((intent) => intent.operation_id), [OPERATION_A], "scanners never infer that prepared work is abandoned");
});

test("handoff, cleanup, and corroboration remain durable outside the instance", (t) => {
  const root = tempRoot(t, "aweb-provision-cleanup-");
  const start = new Date("2026-07-26T00:00:00Z");
  const pending = createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY, authorityHome: join(root, "authority"), now: start,
  });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  const receipt = {
    schema_version: 2,
    mode: "provision-disposable",
    lifecycle: "provisioned",
    cleanup_owner: "instance",
    resource_identity: {
      kind: "provision-operation", operation_id: OPERATION_A, stable_id: null,
      reference: `operation:${OPERATION_A}`, cleanup_authority: "local-controller",
    },
    journal_operation: OPERATION_A,
  };
  const prepared = markProvisionIntentPrepared(root, OPERATION_A, {
    status: "provisioned", operation_id: OPERATION_A, team_id: pending.team_id, alias: pending.alias,
    identity_home: pending.identity_home, did_key: "did:key:z6MkiWorker", certificate_id: "certificate-a",
    agent_id: "agent-a", workspace_id: "workspace-a", registry_url: "https://registry.test", aweb_url: "https://aweb.test",
  }, start);
  assert.equal(markProvisionIntentHandedOff(root, OPERATION_A, start).state, "bound");
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:01Z"), staleAfterMs: 0,
  }), [], "bound work is never scanner-owned");
  writeProvisionCleanupCorroboration(root, "instance-a", receipt);
  assert.deepEqual(loadCleanupCorroboration(join(root, ".corroboration", "cleanup"), "instance-a").receipt, receipt);
  const cleaning = markProvisionIntentCleanupPending(root, OPERATION_A, "retire", start);
  assert.equal(cleaning.state, "cleanup-pending");
  assert.equal(cleaning.cleanup.attempts, 1);
  assert.equal(markProvisionIntentComplete(root, OPERATION_A, start).state, "complete");
  assert.equal(prepared.resource.operation_id, OPERATION_A);

  const abandoned = createProvisionIntent(root, {
    operationID: OPERATION_B, instanceID: "instance-b", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: start,
  });
  assert.equal(markProvisionIntentAbandoned(root, abandoned.operation_id, "no-side-effect", start).state, "complete");
  assert.equal(loadProvisionIntent(root, abandoned.operation_id).resource, null);
});

test("failed recoverable cleanup reaches visible remediable quarantine", (t) => {
  const root = tempRoot(t, "aweb-provision-quarantine-");
  const start = new Date("2026-07-26T00:00:00Z");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: start,
  });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  markProvisionIntentPrepared(root, OPERATION_A, {
    status: "provisioned", operation_id: OPERATION_A, team_id: "backend:acme.test", alias: operationAlias(OPERATION_A),
    identity_home: join(root, ".provisioning", "identities", OPERATION_A), did_key: "did:key:z6MkiWorker",
    certificate_id: "certificate-a", agent_id: "agent-a", workspace_id: "workspace-a",
    registry_url: "https://registry.test", aweb_url: "https://aweb.test",
  }, start);
  markProvisionIntentCleanupPending(root, OPERATION_A, "retire", start);
  const quarantined = markProvisionIntentQuarantined(root, OPERATION_A, "cleanup authority unavailable", start);
  assert.equal(quarantined.state, "quarantined");
  assert.equal(quarantined.cleanup.last_error, "cleanup authority unavailable");
  const retried = retryProvisionIntentQuarantine(root, OPERATION_A, start);
  assert.equal(retried.state, "cleanup-pending");
  assert.equal(retried.cleanup.last_error, "operator retry requested");
});

test("malformed journals quarantine without aborting valid stale recovery", (t) => {
  const root = tempRoot(t, "aweb-provision-corrupt-");
  const start = new Date("2026-07-26T00:00:00Z");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: start,
  });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  writeFileSync(join(root, ".provisioning", "intents", `${OPERATION_B}.json`), '{"schema_version":999}\n', { mode: 0o600 });
  mkdirSync(join(root, ".provisioning", "intents", "malformed.json"));

  const visibleQuarantines = [];
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:01:00Z"), staleAfterMs: 30_000,
    onQuarantine: (report) => visibleQuarantines.push(report),
  }).map((intent) => intent.operation_id), [OPERATION_A]);
  assert.equal(visibleQuarantines.length, 2);
  assert.deepEqual(visibleQuarantines.map((report) => report.source_name).sort(), [`${OPERATION_B}.json`, "malformed.json"].sort());
  assert.equal(visibleQuarantines.every((report) => report.state === "quarantined"), true);
  assert.equal(readdirSync(join(root, ".provisioning", "intents")).includes(`${OPERATION_B}.json`), false);
  const quarantined = readdirSync(join(root, ".provisioning", "quarantine"));
  assert.equal(quarantined.some((name) => name.startsWith(`${OPERATION_B}.json.`) && name.endsWith(".record")), true);
  const reportName = quarantined.find((name) => name.startsWith(`${OPERATION_B}.json.`) && name.endsWith(".report.json"));
  const report = JSON.parse(readFileSync(join(root, ".provisioning", "quarantine", reportName), "utf8"));
  assert.equal(report.state, "quarantined");
  assert.equal(report.cleanup_authority, "none-corrupt-record-not-trusted");
  assert.match(report.error, /invalid/);
});

test("quarantine remains visible when the process dies after its report commit", (t) => {
  const root = tempRoot(t, "aweb-provision-quarantine-crash-");
  const start = new Date("2026-07-26T00:00:00Z");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: start,
  });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  writeFileSync(join(root, ".provisioning", "intents", `${OPERATION_B}.json`), '{"schema_version":999}\n', { mode: 0o600 });
  const journalModule = new URL("../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-journal.mjs", import.meta.url).href;
  const killed = spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { listRecoverableProvisionIntents } from ${JSON.stringify(journalModule)};`,
    `listRecoverableProvisionIntents(${JSON.stringify(root)}, { staleAfterMs: 0, afterQuarantineReport: () => process.exit(73) });`,
  ].join("\n")], { encoding: "utf8" });
  assert.equal(killed.status, 73, killed.stderr);

  const surfaced = [];
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:01:00Z"), staleAfterMs: 30_000,
    onQuarantine: (report) => surfaced.push(report),
  }).map((intent) => intent.operation_id), [OPERATION_A]);
  assert.equal(surfaced.some((report) => report.source_name === `${OPERATION_B}.json`), true);
  assert.equal(readdirSync(join(root, ".provisioning", "intents")).includes(`${OPERATION_B}.json`), false);
});

test("per-intent lock serializes stale takeover, never takes a live holder, and rejects symlinks", async (t) => {
  const root = tempRoot(t, "aweb-provision-lock-");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: new Date("2026-07-26T00:00:00Z"),
  });
  const legacyDatabase = new DatabaseSync(join(root, ".provisioning", "locks.sqlite"));
  legacyDatabase.exec(`CREATE TABLE operation_locks (
    operation_id TEXT PRIMARY KEY, token TEXT NOT NULL, pid INTEGER NOT NULL, acquired_at TEXT NOT NULL
  ) STRICT`);
  legacyDatabase.close();
  const journalModule = new URL("../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-journal.mjs", import.meta.url).href;
  const runWorker = (worker) => new Promise((resolveWorker) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", worker], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => resolveWorker({ status, stderr }));
  });
  const migrationWorker = [
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `try {`,
    `  withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => {`,
    `    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);`,
    `  });`,
    `} catch (error) {`,
    `  if (!/live holder|already locked/.test(error.message)) throw error;`,
    `}`,
  ].join("\n");
  const migrationContenders = await Promise.all(Array.from({ length: 24 }, () => runWorker(migrationWorker)));
  assert.equal(migrationContenders.every((result) => result.status === 0), true, migrationContenders.map((result) => result.stderr).join("\n"));

  withProvisionIntentLock(root, OPERATION_A, () => {
    assert.throws(() => withProvisionIntentLock(root, OPERATION_A, () => {}, {
      now: new Date(Date.now() + 600_000), staleAfterMs: 1,
    }), /live holder/);
  });
  const migratedDatabase = new DatabaseSync(join(root, ".provisioning", "locks.sqlite"));
  assert.equal(migratedDatabase.prepare("PRAGMA table_info(operation_locks)").all().some((column) => column.name === "process_identity"), true);
  migratedDatabase.close();

  const holderReady = join(root, "cross-timezone-holder-ready");
  const timezoneHolder = [
    `import { writeFileSync } from "node:fs";`,
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => {`,
    `  writeFileSync(${JSON.stringify(holderReady)}, "ready");`,
    `  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);`,
    `});`,
  ].join("\n");
  const holder = spawn(process.execPath, ["--input-type=module", "--eval", timezoneHolder], {
    env: { ...process.env, TZ: "UTC" }, stdio: ["ignore", "pipe", "pipe"],
  });
  for (let attempt = 0; attempt < 100 && !existsSync(holderReady); attempt += 1) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  assert.equal(existsSync(holderReady), true, "cross-timezone holder did not acquire its real lock");
  const timezoneContender = [
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `try {`,
    `  withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => console.log("ENTERED"),`,
    `    { now: new Date(Date.now() + 600000), staleAfterMs: 1 });`,
    `} catch (error) {`,
    `  if (!/live holder/.test(error.message)) throw error;`,
    `  console.log("BLOCKED");`,
    `}`,
  ].join("\n");
  const timezoneResult = spawnSync(process.execPath, ["--input-type=module", "--eval", timezoneContender], {
    env: { ...process.env, TZ: "America/Los_Angeles" }, encoding: "utf8",
  });
  assert.equal(timezoneResult.status, 0, timezoneResult.stderr);
  assert.match(timezoneResult.stdout, /BLOCKED/);
  assert.doesNotMatch(timezoneResult.stdout, /ENTERED/);
  await new Promise((resolveHolder, rejectHolder) => {
    holder.on("error", rejectHolder);
    holder.on("close", (status) => status === 0 ? resolveHolder() : rejectHolder(new Error(`holder exited ${status}`)));
  });

  const killed = spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => process.exit(0));`,
  ].join("\n")], { encoding: "utf8" });
  assert.equal(killed.status, 0, killed.stderr);
  let reclaimed = false;
  withProvisionIntentLock(root, OPERATION_A, () => { reclaimed = true; }, {
    now: new Date(Date.now() + 600_000), staleAfterMs: 1,
  });
  assert.equal(reclaimed, true, "a killed holder is transactionally replaced after the stale threshold");

  const reusedPID = spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => process.exit(0));`,
  ].join("\n")], { encoding: "utf8" });
  assert.equal(reusedPID.status, 0, reusedPID.stderr);
  const database = new DatabaseSync(join(root, ".provisioning", "locks.sqlite"));
  database.prepare("UPDATE operation_locks SET pid = ?, process_identity = ? WHERE operation_id = ?")
    .run(process.pid, "prior-boot:reused-pid", OPERATION_A);
  database.close();
  let reclaimedReusedPID = false;
  withProvisionIntentLock(root, OPERATION_A, () => { reclaimedReusedPID = true; }, {
    now: new Date(Date.now() + 600_000), staleAfterMs: 1,
  });
  assert.equal(reclaimedReusedPID, true, "a stale prior-boot row cannot be kept alive by PID reuse");

  const contested = spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => process.exit(0));`,
  ].join("\n")], { encoding: "utf8" });
  assert.equal(contested.status, 0, contested.stderr);
  const winners = join(root, "stale-takeover-winners.txt");
  const worker = [
    `import { appendFileSync } from "node:fs";`,
    `import { withProvisionIntentLock } from ${JSON.stringify(journalModule)};`,
    `try {`,
    `  withProvisionIntentLock(${JSON.stringify(root)}, ${JSON.stringify(OPERATION_A)}, () => {`,
    `    appendFileSync(${JSON.stringify(winners)}, process.pid + "\\n");`,
    `    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);`,
    `  }, { now: new Date(Date.now() + 600000), staleAfterMs: 1 });`,
    `} catch (error) {`,
    `  if (!/live holder|already locked/.test(error.message)) throw error;`,
    `}`,
  ].join("\n");
  const contenders = await Promise.all([runWorker(worker), runWorker(worker)]);
  assert.deepEqual(contenders.map((result) => result.status), [0, 0], contenders.map((result) => result.stderr).join("\n"));
  assert.equal(readFileSync(winners, "utf8").trim().split("\n").length, 1, "exactly one concurrent stale reclaimer may enter");

  const record = join(root, ".provisioning", "intents", `${OPERATION_A}.json`);
  const target = join(root, "substituted.json");
  writeFileSync(target, readFileSync(record));
  // Replace only the final component; same-material links must still be refused.
  unlinkSync(record);
  symlinkSync(target, record);
  assert.throws(() => loadProvisionIntent(root, OPERATION_A), /symbolic link/);
});
