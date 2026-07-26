#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

import {
  attachmentReceipt,
  cleanupJudgement,
  loadCleanupCorroboration,
  pendingProvisionReceipt,
  provisionedDisposableReceipt,
  validateBindingSettings,
} from "../lib/binding-policy.mjs";
import { localControllerMintingAuthorityReceipt } from "../lib/provisioning-authority.mjs";
import {
  createProvisionIntent,
  listRecoverableProvisionIntents,
  loadProvisionIntent,
  markProvisionIntentAbandoned,
  markProvisionIntentCleanupPending,
  markProvisionIntentComplete,
  markProvisionIntentHandedOff,
  markProvisionIntentPrepared,
  markProvisionIntentProvisioning,
  markProvisionIntentQuarantined,
  retryProvisionIntentQuarantine,
  withProvisionIntentLock,
  writeProvisionCleanupCorroboration,
} from "../lib/provisioning-journal.mjs";
import {
  assertPrincipalStoreContained,
  assertPrincipalStoreSafe,
  loadPrincipalDeclaration,
  resolvePrincipalHome,
  resolvePrincipalStore,
  validatePrincipalDeclaration,
} from "../lib/principals.mjs";

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function warning(error) {
  const message = error instanceof Error ? error.message : String(error);
  output({ warning: `aweb-identity-attach: ${message.slice(0, 400)}` });
}

function requiredAbsoluteDirectory(value, name) {
  if (!value || !isAbsolute(value)) throw new TypeError(`${name} must be an absolute path`);
  const path = normalize(resolve(value));
  if (realpathSync(path) !== path) throw new Error(`${name} must be canonical`);
  return path;
}

function parseBindingSettings() {
  let settings;
  try {
    settings = JSON.parse(process.env.OAS_SETTINGS || "{}");
  } catch {
    throw new TypeError("OAS_SETTINGS must be valid JSON");
  }
  return validateBindingSettings(settings?.identity_binding);
}

function exactFields(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const allowed = [...required, ...optional];
  return required.every((field) => Object.hasOwn(value, field))
    && actual.every((field) => allowed.includes(field));
}

function canonicalAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && normalize(resolve(value)) === value;
}

function validatePersistedAttachBinding(binding) {
  const fields = [
    "schema_version", "mode", "cleanup_owner", "principal", "declaration_path",
    "address", "stable_id", "team_id", "soul", "store",
  ];
  if (!exactFields(binding, fields, ["soul_version"])) throw new TypeError("persisted external attach binding has invalid fields");
  if (binding.schema_version !== 1 || binding.mode !== "attach" || binding.cleanup_owner !== "external") {
    throw new TypeError("persisted external attach binding has invalid authority fields");
  }
  if (typeof binding.principal !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(binding.principal)) {
    throw new TypeError("persisted external attach binding has an invalid principal name");
  }
  validatePrincipalDeclaration({
    schema_version: binding.schema_version,
    address: binding.address,
    stable_id: binding.stable_id,
    team_id: binding.team_id,
    soul: binding.soul,
    ...(binding.soul_version === undefined ? {} : { soul_version: binding.soul_version }),
  });
  if (!canonicalAbsolutePath(binding.declaration_path)) throw new TypeError("persisted declaration_path must be canonical and absolute");
  const declarationSuffix = join("oas", "agents", binding.soul, "principals", `${binding.principal}.yaml`);
  if (binding.declaration_path !== declarationSuffix && !binding.declaration_path.endsWith(`${sep}${declarationSuffix}`)) {
    throw new TypeError("persisted declaration_path does not match the principal and soul");
  }
  if (!exactFields(binding.store, ["home", "principal", "credentials", "state"])) {
    throw new TypeError("persisted external attach store has invalid fields");
  }
  for (const [field, path] of Object.entries(binding.store)) {
    if (!canonicalAbsolutePath(path)) throw new TypeError(`persisted store.${field} must be canonical and absolute`);
  }
  assertPrincipalStoreContained(binding.store.home, binding.store);
  const [teamName, teamNamespace] = binding.team_id.split(":");
  const expectedPrincipal = join(binding.store.home, teamName, teamNamespace, binding.stable_id.slice("did:aw:".length));
  if (binding.store.principal !== expectedPrincipal
      || binding.store.credentials !== join(expectedPrincipal, "credentials")
      || binding.store.state !== join(expectedPrincipal, "state")) {
    throw new TypeError("persisted store paths do not match the principal declaration");
  }
  return binding;
}

function parseWhoami(stdout) {
  let identity;
  try {
    identity = JSON.parse(stdout);
  } catch {
    throw new Error("aw whoami returned invalid JSON");
  }
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new Error("aw whoami returned an invalid identity");
  }
  return identity;
}

function parseActiveTeam(stdout, expectedTeamID) {
  let state;
  try {
    state = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team list returned invalid JSON");
  }
  const membership = Array.isArray(state?.memberships)
    ? state.memberships.find((item) => item?.team_id === expectedTeamID && item?.active === true)
    : undefined;
  if (state?.active_team !== expectedTeamID || !membership) {
    throw new Error(`declared principal active team does not match declaration ${JSON.stringify(expectedTeamID)}`);
  }
}

function parseControllerDID(stdout) {
  let authority;
  try {
    authority = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team import-request returned invalid JSON");
  }
  if (typeof authority?.controller_did !== "string" || !/^did:key:z[A-Za-z0-9]+$/.test(authority.controller_did)) {
    throw new Error("local-controller authority did not return a valid controller_did");
  }
  return authority.controller_did;
}

function assertCommittedMintingAuthority(context, declarationPath) {
  const path = relative(context, declarationPath);
  if (!path || path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path)) {
    throw new Error("minting authority declaration must be committed inside OAS_CONTEXT");
  }
  try {
    execFileSync("git", ["-C", context, "ls-files", "--error-unmatch", "--", path], { stdio: "ignore" });
    execFileSync("git", ["-C", context, "diff", "--quiet", "HEAD", "--", path], { stdio: "ignore" });
  } catch {
    throw new Error("minting authority declaration must be committed and unmodified");
  }
}

function resolveAndVerifyDeclaredPrincipal(principal, {
  requireCommittedAuthority = false,
  identityLabel = "attached identity",
} = {}) {
  const instanceHome = requiredAbsoluteDirectory(process.env.OAS_HOME, "OAS_HOME");
  const context = requiredAbsoluteDirectory(process.env.OAS_CONTEXT, "OAS_CONTEXT");
  const soul = process.env.OAS_AGENT;
  if (!soul || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(soul)) {
    throw new TypeError("OAS_AGENT must be a filesystem-safe soul name");
  }

  const declarationFile = join(context, "oas", "agents", soul, "principals", `${principal}.yaml`);
  if (requireCommittedAuthority) assertCommittedMintingAuthority(context, declarationFile);
  const { declaration, path: declarationPath } = loadPrincipalDeclaration(declarationFile);
  if (declaration.soul !== soul) {
    throw new Error(`principal declaration soul ${JSON.stringify(declaration.soul)} does not match OAS_AGENT ${JSON.stringify(soul)}`);
  }

  const store = resolvePrincipalStore(declaration);
  assertPrincipalStoreSafe(store);
  const whoami = parseWhoami(execFileSync(
    "aw",
    ["--identity-home", store.credentials, "whoami", "--json"],
    {
      cwd: instanceHome,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 45000,
      env: { ...process.env, AW_NO_UPDATE_CHECK: "1" },
    },
  ));
  if (whoami.address !== declaration.address) {
    throw new Error(`${identityLabel} address ${JSON.stringify(whoami.address)} does not match declaration ${JSON.stringify(declaration.address)}`);
  }
  if (whoami.stable_id !== declaration.stable_id) {
    throw new Error(`${identityLabel} stable_id ${JSON.stringify(whoami.stable_id)} does not match declaration ${JSON.stringify(declaration.stable_id)}`);
  }
  parseActiveTeam(execFileSync(
    "aw",
    ["--identity-home", store.credentials, "id", "team", "list", "--json"],
    {
      cwd: instanceHome,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 45000,
      env: { ...process.env, AW_NO_UPDATE_CHECK: "1" },
    },
  ), declaration.team_id);
  return { instanceHome, soul, declaration, declarationPath, store };
}

function resolveLocalControllerDID(instanceHome, teamID) {
  const separator = teamID.indexOf(":");
  const team = teamID.slice(0, separator);
  const namespace = teamID.slice(separator + 1);
  return parseControllerDID(execFileSync(
    "aw",
    [
      "id", "team", "import-request",
      "--team", team,
      "--namespace", namespace,
      "--timestamp", "2000-01-01T00:00:00Z",
      "--json",
    ],
    {
      cwd: instanceHome,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 45000,
      env: { ...process.env, AW_NO_UPDATE_CHECK: "1" },
    },
  ));
}

function parseLocalProvisionOutput(stdout, intent) {
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team provision-local returned invalid JSON");
  }
  const fields = [
    "status", "operation_id", "team_id", "alias", "identity_home", "did_key", "certificate_id",
    "agent_id", "workspace_id", "registry_url", "aweb_url",
  ];
  if (!exactFields(result, fields)
      || result.status !== "provisioned"
      || result.operation_id !== intent.operation_id
      || result.team_id !== intent.team_id
      || result.alias !== intent.alias
      || result.identity_home !== intent.identity_home
      || typeof result.did_key !== "string" || !result.did_key.startsWith("did:key:z")
      || typeof result.certificate_id !== "string" || !result.certificate_id
      || typeof result.agent_id !== "string" || !result.agent_id
      || typeof result.workspace_id !== "string" || !result.workspace_id
      || typeof result.registry_url !== "string" || !result.registry_url
      || typeof result.aweb_url !== "string" || !result.aweb_url) {
    throw new Error("aw id team provision-local returned a contradictory resource tuple");
  }
  return result;
}

function runProvisionCommandForIntent(intent, cwd) {
  const creator = intent.authority.intended_creator;
  return parseLocalProvisionOutput(execFileSync(
    "aw",
    [
      "id", "team", "provision-local",
      "--operation-id", intent.operation_id,
      "--team-id", intent.team_id,
      "--name", intent.alias,
      "--authority-identity-home", intent.authority_home,
      "--target-identity-home", intent.identity_home,
      "--authority-address", creator.address,
      "--authority-stable-id", creator.stable_id,
      "--controller-did", intent.authority.controller_did,
      "--json",
    ],
    {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 90000,
      env: { ...process.env, AW_NO_UPDATE_CHECK: "1" },
    },
  ), intent);
}

function runCleanupCommandForIntent(intent, cwd) {
  const creator = intent.authority.intended_creator;
  return parseLocalCleanupOutput(execFileSync(
    "aw",
    [
      "id", "team", "cleanup-local-provision",
      "--operation-id", intent.operation_id,
      "--team-id", intent.team_id,
      "--name", intent.alias,
      "--authority-identity-home", intent.authority_home,
      "--target-identity-home", intent.identity_home,
      "--authority-address", creator.address,
      "--authority-stable-id", creator.stable_id,
      "--controller-did", intent.authority.controller_did,
      "--json",
    ],
    {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 90000,
      env: { ...process.env, AW_NO_UPDATE_CHECK: "1" },
    },
  ), intent.operation_id);
}

function recoverProvisionIntents(principalHome, cwd, { force = false, operationID = null, cleanupUnacknowledged = false } = {}) {
  const intents = operationID === null
    ? listRecoverableProvisionIntents(principalHome, { now: new Date(), staleAfterMs: force ? 0 : 300000 })
    : [loadProvisionIntent(principalHome, operationID)];
  const recovered = [];
  for (const candidate of intents) {
    let result;
    try {
      result = withProvisionIntentLock(principalHome, candidate.operation_id, () => {
        let intent = loadProvisionIntent(principalHome, candidate.operation_id);
        let recoveredProvisioning = false;
        if (cleanupUnacknowledged && !["prepared", "bound"].includes(intent.state)) {
          throw new Error(`operator-confirmed cleanup requires prepared or bound state, found ${intent.state}`);
        }
        if (intent.state === "allocated") {
          markProvisionIntentAbandoned(principalHome, intent.operation_id, "stale-before-first-side-effect");
          return { operation_id: intent.operation_id, outcome: "closed-without-side-effects" };
        }
        if (intent.state === "provisioning") {
          const resource = runProvisionCommandForIntent(intent, cwd);
          intent = markProvisionIntentPrepared(principalHome, intent.operation_id, resource);
          recoveredProvisioning = true;
        }
        if (recoveredProvisioning || (cleanupUnacknowledged && ["prepared", "bound"].includes(intent.state))) {
          const reason = recoveredProvisioning
            ? "orphaned-provisioning-reconciled"
            : intent.state === "prepared" ? "operator-confirmed-unacknowledged-preparation" : "operator-confirmed-unacknowledged-binding";
          intent = markProvisionIntentCleanupPending(principalHome, intent.operation_id, reason);
        }
        if (intent.state === "cleanup-pending") {
          intent = markProvisionIntentCleanupPending(principalHome, intent.operation_id, "recovery-retry");
          const cleanup = runCleanupCommandForIntent(intent, cwd);
          markProvisionIntentComplete(principalHome, intent.operation_id);
          return { operation_id: intent.operation_id, outcome: "cleanup-complete", cleanup };
        }
        return { operation_id: intent.operation_id, outcome: `left-${intent.state}` };
      });
    } catch (error) {
      const failed = loadProvisionIntent(principalHome, candidate.operation_id);
      if (failed.state === "cleanup-pending" && failed.cleanup.attempts >= 3) {
        const message = error instanceof Error ? error.message : String(error);
        result = withProvisionIntentLock(principalHome, failed.operation_id, () => {
          markProvisionIntentQuarantined(principalHome, failed.operation_id, message);
          return { operation_id: failed.operation_id, outcome: "quarantined", error: message.slice(0, 300) };
        });
      } else {
        throw error;
      }
    }
    recovered.push(result);
  }
  return recovered;
}

function runLocalProvision(binding, authority, pendingReceipt) {
  const principalHome = resolvePrincipalHome();
  const recovery = recoverProvisionIntents(principalHome, authority.instanceHome);
  const quarantined = recovery.find((item) => item.outcome === "quarantined");
  if (quarantined) {
    throw new Error(`provision cleanup ${quarantined.operation_id} entered visible quarantine: ${quarantined.error}`);
  }
  const instanceID = process.env.OAS_INSTANCE || "";
  const intent = createProvisionIntent(principalHome, {
    operationID: pendingReceipt.journal_operation,
    instanceID,
    teamID: authority.declaration.team_id,
    authorityHome: authority.store.credentials,
    authority: localControllerMintingAuthorityReceipt({
      principal: binding.minting_authority,
      declarationPath: authority.declarationPath,
      declaration: authority.declaration,
      controllerDID: resolveLocalControllerDID(authority.instanceHome, authority.declaration.team_id),
    }),
  });
  return withProvisionIntentLock(principalHome, intent.operation_id, () => {
    markProvisionIntentProvisioning(principalHome, intent.operation_id);
    const result = runProvisionCommandForIntent(intent, authority.instanceHome);
    markProvisionIntentPrepared(principalHome, intent.operation_id, result);
    const receipt = provisionedDisposableReceipt(pendingReceipt, { cleanupAuthority: "local-controller" });
    writeProvisionCleanupCorroboration(principalHome, instanceID, receipt);
    output({
      meta: {
        identity_binding: receipt,
        minting_authority: intent.authority,
        provisioning: result,
      },
      brief: `Identity: provisioned disposable ${result.alias}; local same-UID cleanup authority is an accident/confused-deputy control, not a boundary against intent.`,
    });
    markProvisionIntentHandedOff(principalHome, intent.operation_id);
  });
}

function attach(binding) {
  const { soul, declaration, declarationPath, store } = resolveAndVerifyDeclaredPrincipal(binding.principal);
  const legacyBinding = validatePersistedAttachBinding({
    schema_version: 1,
    mode: "attach",
    cleanup_owner: "external",
    principal: binding.principal,
    declaration_path: declarationPath,
    address: declaration.address,
    stable_id: declaration.stable_id,
    team_id: declaration.team_id,
    soul: declaration.soul,
    ...(declaration.soul_version === undefined ? {} : { soul_version: declaration.soul_version }),
    store,
  });
  if (binding.legacy) {
    output({
      meta: { identity_binding: legacyBinding },
      brief: `Identity: attached to ${declaration.address} (${declaration.stable_id}); external cleanup ownership preserves the principal when this instance retires.`,
    });
    return;
  }
  output({
    meta: {
      identity_binding: attachmentReceipt({ declarationPath, stableID: declaration.stable_id }),
      attachment: legacyBinding,
    },
    brief: `Identity: attached-existing ${declaration.address} (${declaration.stable_id}); external cleanup ownership preserves the principal when this instance retires.`,
  });
}

function parseLocalCleanupOutput(stdout, operationID) {
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team cleanup-local-provision returned invalid JSON");
  }
  if (!exactFields(result, ["status", "operation_id", "grants", "workspace", "identity", "certificate", "credentials", "audit"])
      || result.status !== "complete"
      || result.operation_id !== operationID
      || result.grants !== "physically-absent"
      || result.workspace !== "soft-deleted"
      || result.identity !== "soft-deleted"
      || result.certificate !== "revoked"
      || result.credentials !== "physically-absent"
      || result.audit !== "intentionally-retained-operation-record") {
    throw new Error("aw id team cleanup-local-provision returned a contradictory cleanup tuple");
  }
  return result;
}

function executeLocalCleanup(receipt, instanceID) {
  const principalHome = resolvePrincipalHome();
  const operationID = receipt.journal_operation;
  return withProvisionIntentLock(principalHome, operationID, () => {
    let intent = loadProvisionIntent(principalHome, operationID);
    if (intent.instance_id !== instanceID || intent.authority.path !== "local-controller" || intent.resource?.operation_id !== operationID) {
      throw new Error("cleanup journal does not corroborate this instance and provisioned resource");
    }
    if (intent.state === "complete") {
      return {
        status: "complete", operation_id: operationID, grants: "physically-absent", workspace: "soft-deleted",
        identity: "soft-deleted", certificate: "revoked", credentials: "physically-absent", audit: "intentionally-retained-operation-record",
      };
    }
    intent = markProvisionIntentCleanupPending(principalHome, operationID, "ordinary-retire");
    const result = runCleanupCommandForIntent(intent, requiredAbsoluteDirectory(process.env.OAS_HOME, "OAS_HOME"));
    markProvisionIntentComplete(principalHome, operationID);
    return result;
  });
}

function retire() {
  let recoveryWarning = null;
  try {
    if (process.env.OAS_HOME) {
      const recovered = recoverProvisionIntents(
        resolvePrincipalHome(),
        requiredAbsoluteDirectory(process.env.OAS_HOME, "OAS_HOME"),
      );
      const quarantined = recovered.find((item) => item.outcome === "quarantined");
      if (quarantined) recoveryWarning = `aweb-identity-attach: cleanup ${quarantined.operation_id} entered visible quarantine: ${quarantined.error}`;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    recoveryWarning = `aweb-identity-attach: another disposable cleanup remains pending: ${message.slice(0, 300)}`;
  }
  let metadata;
  try {
    metadata = JSON.parse(process.env.OAS_META || "{}");
  } catch {
    const digest = createHash("sha256").update(process.env.OAS_META || "").digest("hex");
    output({
      meta: {
        identity_binding_evidence: { format: "unparseable", sha256: digest },
        retirement: { action: "preserve", cleanup_authorized: false, reason: "unparseable_instance_metadata" },
      },
      ...(recoveryWarning ? { warning: recoveryWarning } : {}),
    });
    return;
  }
  try {
    const legacy = validatePersistedAttachBinding(metadata?.identity_binding);
    output({
      meta: {
        identity_binding: legacy,
        retirement: { action: "preserve_principal", cleanup_owner: "external" },
      },
      ...(recoveryWarning ? { warning: recoveryWarning } : {}),
    });
    return;
  } catch {
    // v2 judgements below preserve on every invalid or unattributable receipt.
  }
  const instanceID = process.env.OAS_INSTANCE || "";
  const corroborationHome = join(resolvePrincipalHome(), ".corroboration", "cleanup");
  let corroboration = null;
  try {
    corroboration = loadCleanupCorroboration(corroborationHome, instanceID);
  } catch {
    corroboration = null;
  }
  const judgement = cleanupJudgement(metadata?.identity_binding, corroboration, instanceID);
  if (judgement.cleanup_authorized && judgement.authority_scope === "local_same_uid_accident_guard") {
    try {
      const cleanup = executeLocalCleanup(metadata.identity_binding, instanceID);
      output({
        meta: {
          identity_binding_evidence: metadata.identity_binding,
          retirement: { ...judgement, action: "cleanup_complete", cleanup },
        },
        ...(recoveryWarning ? { warning: recoveryWarning } : {}),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      output({
        meta: {
          identity_binding_evidence: metadata.identity_binding,
          retirement: { ...judgement, action: "cleanup_pending", cleanup_complete: false },
        },
        warning: `aweb-identity-attach: disposable cleanup remains durably pending: ${message.slice(0, 300)}`,
      });
    }
    return;
  }
  output({
    meta: {
      identity_binding_evidence: metadata?.identity_binding ?? null,
      retirement: judgement,
    },
    ...(recoveryWarning ? { warning: recoveryWarning } : {}),
  });
}

const event = process.env.OAS_EVENT || process.argv[2];
try {
  if (event === "spawn") {
    const binding = parseBindingSettings();
    if (binding.mode === "attach" || binding.mode === "attach-existing") attach(binding);
    else if (binding.mode === "provision-durable") {
      throw new TypeError("provision-durable is declared but not executable; durable minting authority belongs to aaaa.39");
    } else {
      if (binding.minting_authority_path === "hosted") {
        throw new TypeError("hosted provision-disposable is refused before creation: no scoped non-ambient authority can clean a committed hosted member; an owner/admin API key must never be exposed to the same-UID model");
      }
      const authority = resolveAndVerifyDeclaredPrincipal(binding.minting_authority, {
        requireCommittedAuthority: true,
        identityLabel: "minting authority credentials",
      });
      runLocalProvision(binding, authority, pendingProvisionReceipt(binding));
    }
  } else if (event === "retire") retire();
  else if (event === "reconcile") {
    const principalHome = resolvePrincipalHome();
    let operationID = null;
    let cleanupUnacknowledged = false;
    if (process.argv[3] === "--retry-quarantine") {
      if (!process.argv[4] || process.argv.length !== 5) throw new TypeError("reconcile --retry-quarantine requires exactly one operation id");
      operationID = process.argv[4];
      retryProvisionIntentQuarantine(principalHome, operationID);
    } else if (process.argv[3] === "--cleanup-unacknowledged") {
      if (!process.argv[4] || process.argv.length !== 5) throw new TypeError("reconcile --cleanup-unacknowledged requires exactly one operation id");
      operationID = process.argv[4];
      cleanupUnacknowledged = true;
    } else if (process.argv.length !== 3) {
      throw new TypeError("reconcile accepts --cleanup-unacknowledged <operation-id> or --retry-quarantine <operation-id>");
    }
    const recovered = recoverProvisionIntents(principalHome, realpathSync(process.cwd()), {
      force: true,
      operationID,
      cleanupUnacknowledged,
    });
    output({ status: "reconciled", operations: recovered });
  } else throw new TypeError(`unsupported lifecycle event ${JSON.stringify(event)}`);
} catch (error) {
  warning(error);
}
