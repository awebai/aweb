#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
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
  loadProvisionIntentForRecovery,
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

function parseSettingsJSON(encoded, source) {
  let settings;
  try {
    settings = JSON.parse(encoded || "{}");
  } catch {
    throw new TypeError(`${source} must be valid JSON`);
  }
  if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
    throw new TypeError(`${source} must contain a settings object`);
  }
  return settings;
}

function parseBindingSettings() {
  return validateBindingSettings(parseSettingsJSON(process.env.OAS_SETTINGS, "OAS_SETTINGS")?.identity_binding);
}

class ReadinessIssue extends Error {
  constructor(readiness, message, nextAction) {
    super(message);
    this.readiness = readiness;
    this.nextAction = nextAction;
  }
}

class SpawnRefusal extends Error {
  constructor(issue) {
    super(issue.message);
    this.issue = issue;
  }
}

function shellWord(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function safeSoul(value, name = "OAS_AGENT") {
  if (!value || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    throw new TypeError(`${name} must be a filesystem-safe soul name`);
  }
  return value;
}

function oneNextAction(issue, soul) {
  if (issue?.nextAction) return issue.nextAction;
  if (soul) return `oas aweb-identity status --soul ${shellWord(safeSoul(soul))} --json`;
  return "oas status --json";
}

function editConfigCommand(context) {
  return `$EDITOR ${shellWord(join(context, "oas-config.yaml"))}`;
}

function readinessReport({ readiness, message, nextAction, settingsSource }) {
  return {
    schema_version: 1,
    capability: "aweb.identity-attach",
    readiness,
    release_stage: "experimental-internal",
    settings_source: settingsSource,
    identity_resources_created: false,
    instance_or_session_created: false,
    admission: "advisory-status-cannot-prevent-oas-launch",
    message,
    next_action: nextAction,
  };
}

function commandSoul() {
  const index = process.argv.indexOf("--soul");
  if (index < 0) return null;
  return safeSoul(process.argv[index + 1], "status --soul");
}

function resolvedStatusSettings(context, soul) {
  const doctorArgs = ["doctor", context, ...(soul ? ["--soul", soul] : []), "--json"];
  const testRoot = process.env.OAS_TEST_ROOT;
  const command = testRoot ? process.execPath : "oas";
  const args = testRoot ? [join(testRoot, "bin", "oas.mjs"), ...doctorArgs] : doctorArgs;
  const document = parseSettingsJSON(execFileSync(command, args, {
    cwd: context, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 45000,
  }), "oas doctor --json output");
  const capability = Array.isArray(document.capabilities)
    ? document.capabilities.find((item) => item?.id === "aweb.identity-attach")
    : null;
  if (!capability) throw new ReadinessIssue("experimental", "aweb identity capability is not active for this selection", "Activate the internal capability only in a controlled development configuration.");
  return {
    settings: capability.settings || {},
    source: `resolved-oas-config${soul ? `:soul=${soul}` : ":global"}`,
  };
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
  instanceHome: requestedInstanceHome = process.env.OAS_HOME,
  context: requestedContext = process.env.OAS_CONTEXT,
  soul: requestedSoul = process.env.OAS_AGENT,
} = {}) {
  const instanceHome = requiredAbsoluteDirectory(requestedInstanceHome, "OAS_HOME");
  const context = requiredAbsoluteDirectory(requestedContext, "OAS_CONTEXT");
  const soul = requestedSoul;
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

function preflightBinding(binding, {
  instanceHome = process.env.OAS_HOME,
  context = process.env.OAS_CONTEXT,
  soul = process.env.OAS_AGENT,
} = {}) {
  if (binding.mode === "attach" || binding.mode === "attach-existing") {
    return {
      binding,
      principal: resolveAndVerifyDeclaredPrincipal(binding.principal, { instanceHome, context, soul }),
    };
  }
  if (binding.mode === "provision-durable") {
    throw new ReadinessIssue(
      "experimental",
      "provision-durable is declared but not executable; durable minting authority belongs to aaaa.39",
      "Use the temporary-worker journey; do not attempt durable resident setup.",
    );
  }
  if (binding.minting_authority_path === "hosted") {
    throw new ReadinessIssue(
      "experimental",
      "hosted provision-disposable is refused before creation: no scoped non-ambient authority can clean a committed hosted member; an owner/admin API key must never be exposed to the same-UID model",
      "Use only the controlled local-team development journey.",
    );
  }
  const authority = resolveAndVerifyDeclaredPrincipal(binding.minting_authority, {
    requireCommittedAuthority: true,
    identityLabel: "minting authority credentials",
    instanceHome,
    context,
    soul,
  });
  return {
    binding,
    authority,
    controllerDID: resolveLocalControllerDID(authority.instanceHome, authority.declaration.team_id),
  };
}

function bindingReadiness(settings, { context, soul, settingsSource }) {
  if (!soul) {
    const issue = new ReadinessIssue(
      "needs_setup",
      "a soul selection is required because spawn resolves settings per soul and agent type",
      "oas status --json",
    );
    return readinessReport({ readiness: issue.readiness, message: issue.message, nextAction: issue.nextAction, settingsSource });
  }
  let binding;
  try {
    binding = validateBindingSettings(settings?.identity_binding);
    preflightBinding(binding, { instanceHome: context, context, soul });
  } catch (error) {
    const issue = error instanceof ReadinessIssue
      ? error
      : new ReadinessIssue(
        settings?.identity_binding == null || settings?.identity_binding?.mode === "provision-durable" ? "experimental" : "needs_setup",
        error instanceof Error ? error.message : String(error),
        settings?.identity_binding == null
          ? "Do not spawn: no supported one-command identity setup exists yet."
          : settings?.identity_binding?.mode === "provision-durable"
            ? "Do not spawn: durable resident setup is not available."
            : editConfigCommand(context),
      );
    return readinessReport({
      readiness: issue.readiness,
      message: issue.message,
      nextAction: oneNextAction(issue, soul),
      settingsSource,
    });
  }
  return readinessReport({
    readiness: "ready",
    message: "selected settings and declared authority passed the same non-mutating preflight used by spawn",
    nextAction: null,
    settingsSource,
  });
}

function status() {
  const allowed = new Set(["status", "--soul", "--json"]);
  for (let index = 2; index < process.argv.length; index += 1) {
    const value = process.argv[index];
    if (!allowed.has(value) && process.argv[index - 1] !== "--soul") throw new TypeError(`unsupported status argument ${JSON.stringify(value)}`);
  }
  const context = requiredAbsoluteDirectory(realpathSync(process.cwd()), "status context");
  const soul = commandSoul();
  let resolved;
  try {
    resolved = resolvedStatusSettings(context, soul);
  } catch (error) {
    const issue = error instanceof ReadinessIssue
      ? error
      : new ReadinessIssue("experimental", error instanceof Error ? error.message : String(error), "Repair OAS configuration resolution before spawning.");
    const report = readinessReport({ readiness: issue.readiness, message: issue.message, nextAction: oneNextAction(issue, soul), settingsSource: "unresolved-oas-config" });
    output(report);
    process.exitCode = 1;
    return;
  }
  const report = bindingReadiness(resolved.settings, { context, soul, settingsSource: resolved.source });
  output(report);
  if (report.readiness !== "ready") process.exitCode = 1;
}

function parseLocalProvisionOutput(stdout, intent) {
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team provision-local returned invalid JSON");
  }
  const fields = [
    "status", "operation_id", "team_id", "alias", "name", "identity_home", "did_key", "certificate_id",
    "agent_id", "workspace_id", "registry_url", "aweb_url",
  ];
  if (!exactFields(result, fields)
      || result.status !== "provisioned"
      || result.operation_id !== intent.operation_id
      || result.team_id !== intent.team_id
      || result.alias !== intent.alias
      || result.name !== intent.alias
      || result.identity_home !== intent.identity_home
      || typeof result.did_key !== "string" || !result.did_key.startsWith("did:key:z")
      || typeof result.certificate_id !== "string" || !result.certificate_id
      || typeof result.agent_id !== "string" || !result.agent_id
      || typeof result.workspace_id !== "string" || !result.workspace_id
      || typeof result.registry_url !== "string" || !result.registry_url
      || typeof result.aweb_url !== "string" || !result.aweb_url) {
    throw new Error("aw id team provision-local returned a contradictory resource tuple");
  }
  const { name: _normalizedName, ...resource } = result;
  return resource;
}

function runProvisionCommandForIntent(intent, cwd) {
  const creator = intent.authority.intended_creator;
  let stdout;
  try {
    stdout = execFileSync(
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
    );
  } catch (error) {
    const detail = typeof error?.stderr === "string" ? error.stderr.trim() : "";
    throw new Error(`aw id team provision-local failed: ${detail || error.message}`);
  }
  return parseLocalProvisionOutput(stdout, intent);
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

function recoverProvisionIntents(principalHome, cwd, {
  force = false, operationID = null, cleanupUnacknowledged = false, retryQuarantine = false,
} = {}) {
  const malformed = [];
  const onQuarantine = (report) => malformed.push(report);
  const exactIntent = operationID === null ? null : loadProvisionIntentForRecovery(principalHome, operationID, { onQuarantine });
  const intents = operationID === null
    ? listRecoverableProvisionIntents(principalHome, {
        now: new Date(),
        staleAfterMs: force ? 0 : 300000,
        onQuarantine,
      })
    : exactIntent ? [exactIntent] : [];
  const recovered = malformed.map((report) => ({
    operation_id: report.source_name.replace(/\.json$/, ""),
    outcome: "quarantined",
    error: report.error,
  }));
  for (const candidate of intents) {
    let result;
    try {
      result = withProvisionIntentLock(principalHome, candidate.operation_id, () => {
        let intent = loadProvisionIntent(principalHome, candidate.operation_id);
        if (retryQuarantine) intent = retryProvisionIntentQuarantine(principalHome, intent.operation_id);
        let recoveredProvisioning = false;
        let cleanupAttemptStarted = false;
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
          cleanupAttemptStarted = true;
        }
        if (intent.state === "cleanup-pending") {
          if (!cleanupAttemptStarted) intent = markProvisionIntentCleanupPending(principalHome, intent.operation_id, "recovery-retry");
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

function runLocalProvision(binding, authority, controllerDID, pendingReceipt) {
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
      controllerDID,
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

function attach(binding, verifiedPrincipal = null) {
  const { soul, declaration, declarationPath, store } = verifiedPrincipal || resolveAndVerifyDeclaredPrincipal(binding.principal);
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
  if (event === "status") status();
  else if (event === "spawn") {
    let binding;
    let preflight;
    try {
      safeSoul(process.env.OAS_AGENT);
      binding = parseBindingSettings();
      preflight = preflightBinding(binding);
    } catch (error) {
      const durableUnavailable = error instanceof Error && /durable resident provisioning/.test(error.message);
      const issue = error instanceof ReadinessIssue
        ? error
        : new ReadinessIssue(
          durableUnavailable ? "experimental" : "needs_setup",
          durableUnavailable
            ? "provision-durable is declared but not executable; durable minting authority belongs to aaaa.39"
            : error instanceof Error ? error.message : String(error),
          null,
        );
      throw new SpawnRefusal(issue);
    }
    if (binding.mode === "attach" || binding.mode === "attach-existing") attach(binding, preflight.principal);
    else runLocalProvision(binding, preflight.authority, preflight.controllerDID, pendingProvisionReceipt(binding));
  } else if (event === "retire") retire();
  else if (event === "reconcile") {
    const principalHome = resolvePrincipalHome();
    let operationID = null;
    let cleanupUnacknowledged = false;
    let retryQuarantine = false;
    if (process.argv[3] === "--operation") {
      if (!process.argv[4] || process.argv.length !== 5) throw new TypeError("reconcile --operation requires exactly one operation id");
      operationID = process.argv[4];
    } else if (process.argv[3] === "--retry-quarantine") {
      if (!process.argv[4] || process.argv.length !== 5) throw new TypeError("reconcile --retry-quarantine requires exactly one operation id");
      operationID = process.argv[4];
      retryQuarantine = true;
    } else if (process.argv[3] === "--cleanup-unacknowledged") {
      if (!process.argv[4] || process.argv.length !== 5) throw new TypeError("reconcile --cleanup-unacknowledged requires exactly one operation id");
      operationID = process.argv[4];
      cleanupUnacknowledged = true;
    } else {
      throw new TypeError("reconcile requires exactly one operation id via --operation, --cleanup-unacknowledged, or --retry-quarantine");
    }
    const recovered = recoverProvisionIntents(principalHome, realpathSync(process.cwd()), {
      force: true,
      operationID,
      cleanupUnacknowledged,
      retryQuarantine,
    });
    output({ status: "reconciled", operations: recovered });
    if (recovered.some((item) => item.outcome === "quarantined")) process.exitCode = 1;
  } else throw new TypeError(`unsupported lifecycle event ${JSON.stringify(event)}`);
} catch (error) {
  if (event === "spawn" && error instanceof SpawnRefusal) {
    const refusal = {
      schema_version: 1,
      status: "unservable",
      readiness: error.issue.readiness,
      release_stage: "experimental-internal",
      nothing_created_by_capability: true,
      identity_resources_created: false,
      admission: "advisory-hook-failure-cannot-prevent-oas-launch",
      message: error.message,
      next_action: process.env.OAS_AGENT && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(process.env.OAS_AGENT)
        ? `oas aweb-identity status --soul ${shellWord(process.env.OAS_AGENT)} --json`
        : "oas status --json",
    };
    if (Object.hasOwn(process.env, "OAS_ROOT")) {
      // OAS 0.18 hooks are advisory. Preserve the specific refusal in its
      // structured warning instead of letting execSync replace it with a
      // truncated command path. Required-hook nonzero admission belongs to .2.
      output({ ...refusal, warning: `aweb-identity-attach: ${error.message}; NOTHING CREATED by this capability; next action: ${refusal.next_action}` });
    } else {
      output(refusal);
      process.stderr.write(`aweb-identity-attach: ${error.message.slice(0, 110)}; NOTHING CREATED by this capability; OAS hook admission remains advisory\n`);
      process.exitCode = 1;
    }
  } else {
    warning(error);
    if (event === "reconcile" || event === "status") process.exitCode = 1;
  }
}
