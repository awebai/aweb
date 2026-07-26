import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  assert.equal(intent.alias, OPERATION_A);
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
    alias: OPERATION_B,
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
    now: new Date("2026-07-26T00:00:31Z"), staleAfterMs: 30_000, includePrepared: true,
  }).map((intent) => intent.operation_id), [OPERATION_A, OPERATION_B], "explicit operator recovery may clean a prepared-but-unhanded identity");
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
    status: "provisioned", operation_id: OPERATION_A, team_id: "backend:acme.test", alias: OPERATION_A,
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

test("per-intent lock excludes a concurrent scanner and rejects symlink substitution", (t) => {
  const root = tempRoot(t, "aweb-provision-lock-");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    authorityHome: join(root, "authority"), now: new Date("2026-07-26T00:00:00Z"),
  });
  withProvisionIntentLock(root, OPERATION_A, () => {
    assert.throws(() => withProvisionIntentLock(root, OPERATION_A, () => {}), /already locked/);
  });

  const record = join(root, ".provisioning", "intents", `${OPERATION_A}.json`);
  const target = join(root, "substituted.json");
  writeFileSync(target, readFileSync(record));
  // Replace only the final component; same-material links must still be refused.
  unlinkSync(record);
  symlinkSync(target, record);
  assert.throws(() => loadProvisionIntent(root, OPERATION_A), /symbolic link/);
});
