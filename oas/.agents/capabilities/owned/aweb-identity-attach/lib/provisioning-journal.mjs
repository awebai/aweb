import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join, normalize, parse, relative, resolve, sep } from "node:path";

import { cleanupCorroborationPayload, validateBindingReceipt } from "./binding-policy.mjs";
import { validateMintingAuthorityReceipt } from "./provisioning-authority.mjs";

const OPERATION_ID = /^oas-[A-Za-z0-9_-]{21}[AQgw]$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const TEAM_ID = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const RECOVERABLE_STATES = new Set(["allocated", "provisioning", "cleanup-pending"]);
const INTENT_FIELDS = [
  "schema_version", "operation_id", "instance_id", "mode", "authority", "authority_home", "team_id", "alias",
  "identity_home", "state", "resource", "cleanup", "revision", "created_at", "updated_at",
];
const RESOURCE_FIELDS = [
  "status", "operation_id", "team_id", "alias", "identity_home", "did_key", "certificate_id",
  "agent_id", "workspace_id", "registry_url", "aweb_url",
];

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
}

function canonicalRoot(value) {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(resolve(value)) !== value) {
    throw new TypeError("provision journal home must be canonical and absolute");
  }
  assertNoSymlink(value, "provision journal home");
  return value;
}

function assertNoSymlink(path, label) {
  const root = parse(path).root;
  let current = root;
  for (const component of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, component);
    if (!existsSync(current)) return;
    if (lstatSync(current).isSymbolicLink()) throw new Error(`${label} contains a symbolic link: ${current}`);
  }
}

function paths(home) {
  const root = join(canonicalRoot(home), ".provisioning");
  const intents = join(root, "intents");
  const identities = join(root, "identities");
  const locks = join(root, "locks");
  for (const path of [root, intents, identities, locks]) {
    assertNoSymlink(path, "provision journal path");
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return { root, intents, identities, locks };
}

function validatedOperationID(value) {
  if (typeof value !== "string" || !OPERATION_ID.test(value)) throw new TypeError("invalid provision operation id");
  return value;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("journal timestamp is invalid");
  return date.toISOString();
}

function intentPath(home, operation) {
  return join(paths(home).intents, `${validatedOperationID(operation)}.json`);
}

function validateResource(resource, intent) {
  if (!exactFields(resource, RESOURCE_FIELDS)
      || resource.status !== "provisioned"
      || resource.operation_id !== intent.operation_id
      || resource.team_id !== intent.team_id
      || resource.alias !== intent.alias
      || resource.identity_home !== intent.identity_home
      || typeof resource.did_key !== "string" || !resource.did_key.startsWith("did:key:z")
      || typeof resource.certificate_id !== "string" || resource.certificate_id.length === 0
      || typeof resource.agent_id !== "string" || resource.agent_id.length === 0
      || typeof resource.workspace_id !== "string" || resource.workspace_id.length === 0
      || typeof resource.registry_url !== "string" || resource.registry_url.length === 0
      || typeof resource.aweb_url !== "string" || resource.aweb_url.length === 0) {
    throw new TypeError("provisioned resource tuple is invalid or contradictory");
  }
  return resource;
}

function validateIntent(intent) {
  if (!exactFields(intent, INTENT_FIELDS)
      || intent.schema_version !== 1
      || !OPERATION_ID.test(intent.operation_id)
      || typeof intent.instance_id !== "string" || !SAFE_ID.test(intent.instance_id)
      || intent.mode !== "provision-disposable"
      || typeof intent.authority_home !== "string" || !isAbsolute(intent.authority_home) || normalize(resolve(intent.authority_home)) !== intent.authority_home
      || typeof intent.team_id !== "string" || !TEAM_ID.test(intent.team_id)
      || intent.alias !== intent.operation_id
      || typeof intent.identity_home !== "string" || !isAbsolute(intent.identity_home)
      || !["allocated", "provisioning", "prepared", "bound", "cleanup-pending", "complete", "quarantined"].includes(intent.state)
      || !exactFields(intent.cleanup, ["attempts", "last_error"])
      || !Number.isInteger(intent.cleanup.attempts) || intent.cleanup.attempts < 0
      || (intent.cleanup.last_error !== null && typeof intent.cleanup.last_error !== "string")
      || !Number.isInteger(intent.revision) || intent.revision < 1
      || typeof intent.created_at !== "string" || !Number.isFinite(Date.parse(intent.created_at))
      || typeof intent.updated_at !== "string" || !Number.isFinite(Date.parse(intent.updated_at))) {
    throw new TypeError("provision intent journal record is invalid");
  }
  const authority = validateMintingAuthorityReceipt(intent.authority);
  if (authority.path !== "local-controller" || authority.intended_creator.team_id !== intent.team_id) {
    throw new TypeError("provision intent authority contradicts its team or path");
  }
  if (["prepared", "bound"].includes(intent.state)) validateResource(intent.resource, intent);
  else if (intent.resource !== null && !["cleanup-pending", "complete", "quarantined"].includes(intent.state)) {
    throw new TypeError("provision intent resource is present before preparation");
  } else if (intent.resource !== null) validateResource(intent.resource, intent);
  return intent;
}

function writeNew(path, value) {
  const encoded = `${JSON.stringify(value, null, 2)}\n`;
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, encoded);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function replace(path, value) {
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  const fd = openSync(temp, "r");
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temp, path);
}

export function createProvisionIntent(home, { operationID, instanceID, teamID, authority, authorityHome, now = new Date() }) {
  const operation = validatedOperationID(operationID);
  if (typeof instanceID !== "string" || !SAFE_ID.test(instanceID)) throw new TypeError("provision instance id must be filesystem-safe");
  validateMintingAuthorityReceipt(authority);
  if (typeof authorityHome !== "string" || !isAbsolute(authorityHome) || normalize(resolve(authorityHome)) !== authorityHome) {
    throw new TypeError("provision authority home must be canonical and absolute");
  }
  assertNoSymlink(authorityHome, "provision authority home");
  const journalPaths = paths(home);
  const path = join(journalPaths.intents, `${operation}.json`);
  if (existsSync(path)) {
    const existing = loadProvisionIntent(home, operation);
    if (existing.instance_id !== instanceID) throw new Error(`provision operation ${operation} already belongs to instance ${existing.instance_id}`);
    return existing;
  }
  const time = timestamp(now);
  const intent = validateIntent({
    schema_version: 1,
    operation_id: operation,
    instance_id: instanceID,
    mode: "provision-disposable",
    authority,
    authority_home: authorityHome,
    team_id: teamID,
    alias: operation,
    identity_home: join(journalPaths.identities, operation),
    state: "allocated",
    resource: null,
    cleanup: { attempts: 0, last_error: null },
    revision: 1,
    created_at: time,
    updated_at: time,
  });
  writeNew(path, intent);
  return intent;
}

export function loadProvisionIntent(home, operation) {
  const path = intentPath(home, operation);
  assertNoSymlink(path, "provision intent record");
  const info = lstatSync(path);
  if (!info.isFile()) throw new Error("provision intent record must be a regular file");
  return validateIntent(JSON.parse(readFileSync(path, "utf8")));
}

function transition(home, operation, state, now, resource) {
  const intent = loadProvisionIntent(home, operation);
  const next = validateIntent({
    ...intent,
    state,
    resource: resource === undefined ? intent.resource : resource,
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  });
  replace(intentPath(home, operation), next);
  return next;
}

export function markProvisionIntentProvisioning(home, operation, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "allocated") throw new Error(`cannot begin provisioning from ${intent.state}`);
  return transition(home, operation, "provisioning", now);
}

export function markProvisionIntentPrepared(home, operation, resource, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "provisioning") throw new Error(`cannot prepare binding from ${intent.state}`);
  validateResource(resource, intent);
  return transition(home, operation, "prepared", now, resource);
}

export function markProvisionIntentHandedOff(home, operation, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "prepared") throw new Error(`cannot record binding handoff from ${intent.state}`);
  return transition(home, operation, "bound", now);
}

export function markProvisionIntentCleanupPending(home, operation, reason, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (!["prepared", "bound", "cleanup-pending"].includes(intent.state)) {
    throw new Error(`cannot begin cleanup from ${intent.state}`);
  }
  if (typeof reason !== "string" || reason.length === 0) throw new TypeError("cleanup reason is required");
  const next = validateIntent({
    ...intent,
    state: "cleanup-pending",
    cleanup: { attempts: intent.cleanup.attempts + 1, last_error: reason.slice(0, 400) },
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  });
  replace(intentPath(home, operation), next);
  return next;
}

export function markProvisionIntentAbandoned(home, operation, reason, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "allocated" || intent.resource !== null) throw new Error(`cannot abandon provision intent from ${intent.state}`);
  if (typeof reason !== "string" || reason.length === 0) throw new TypeError("abandon reason is required");
  const next = {
    ...intent,
    state: "complete",
    cleanup: { attempts: intent.cleanup.attempts, last_error: reason.slice(0, 400) },
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  };
  validateIntent(next);
  replace(intentPath(home, operation), next);
  return next;
}

export function markProvisionIntentComplete(home, operation, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "cleanup-pending") throw new Error(`cannot complete cleanup from ${intent.state}`);
  const next = {
    ...intent,
    state: "complete",
    cleanup: { ...intent.cleanup, last_error: null },
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  };
  validateIntent(next);
  replace(intentPath(home, operation), next);
  return next;
}

export function markProvisionIntentQuarantined(home, operation, reason, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "cleanup-pending") throw new Error(`cannot quarantine cleanup from ${intent.state}`);
  if (typeof reason !== "string" || reason.length === 0) throw new TypeError("quarantine reason is required");
  const next = {
    ...intent,
    state: "quarantined",
    cleanup: { ...intent.cleanup, last_error: reason.slice(0, 400) },
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  };
  validateIntent(next);
  replace(intentPath(home, operation), next);
  return next;
}

export function retryProvisionIntentQuarantine(home, operation, now = new Date()) {
  const intent = loadProvisionIntent(home, operation);
  if (intent.state !== "quarantined") throw new Error(`cannot retry quarantine from ${intent.state}`);
  const next = {
    ...intent,
    state: "cleanup-pending",
    cleanup: { ...intent.cleanup, last_error: "operator retry requested" },
    revision: intent.revision + 1,
    updated_at: timestamp(now),
  };
  validateIntent(next);
  replace(intentPath(home, operation), next);
  return next;
}

export function writeProvisionCleanupCorroboration(home, instanceID, receipt) {
  canonicalRoot(home);
  if (typeof instanceID !== "string" || !SAFE_ID.test(instanceID)) throw new TypeError("corroboration instance id must be filesystem-safe");
  validateBindingReceipt(receipt);
  const directory = join(home, ".corroboration", "cleanup");
  assertNoSymlink(directory, "cleanup corroboration path");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const record = { schema_version: 1, corroboration_class: "local-same-uid", instance_id: instanceID, receipt };
  const encoded = {
    ...record,
    digest: createHash("sha256").update(cleanupCorroborationPayload(record)).digest("hex"),
  };
  const path = join(directory, `${instanceID}.json`);
  if (existsSync(path)) {
    assertNoSymlink(path, "cleanup corroboration record");
    const existing = JSON.parse(readFileSync(path, "utf8"));
    if (JSON.stringify(existing) !== JSON.stringify(encoded)) throw new Error("cleanup corroboration already exists with different authority");
    return path;
  }
  writeNew(path, encoded);
  return path;
}

export function listRecoverableProvisionIntents(home, { now = new Date(), staleAfterMs }) {
  if (!Number.isFinite(staleAfterMs) || staleAfterMs < 0) throw new TypeError("staleAfterMs must be non-negative");
  const cutoff = new Date(now).getTime() - staleAfterMs;
  return readdirSync(paths(home).intents, { withFileTypes: true })
    .filter((entry) => entry.name.endsWith(".json"))
    .map((entry) => loadProvisionIntent(home, entry.name.slice(0, -5)))
    .filter((intent) => RECOVERABLE_STATES.has(intent.state) && Date.parse(intent.updated_at) <= cutoff)
    .sort((left, right) => left.operation_id.localeCompare(right.operation_id));
}

export function withProvisionIntentLock(home, operation, callback, { now = new Date(), staleAfterMs = 300_000 } = {}) {
  if (typeof callback !== "function") throw new TypeError("provision lock callback is required");
  const lockPath = join(paths(home).locks, `${validatedOperationID(operation)}.lock`);
  try {
    const fd = openSync(lockPath, "wx", 0o600);
    try {
      writeSync(fd, `${timestamp(now)}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    assertNoSymlink(lockPath, "provision intent lock");
    const age = new Date(now).getTime() - statSync(lockPath).mtimeMs;
    if (age <= staleAfterMs) throw new Error(`provision operation ${operation} is already locked`);
    unlinkSync(lockPath);
    return withProvisionIntentLock(home, operation, callback, { now, staleAfterMs });
  }
  try {
    return callback();
  } finally {
    try { unlinkSync(lockPath); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
}
