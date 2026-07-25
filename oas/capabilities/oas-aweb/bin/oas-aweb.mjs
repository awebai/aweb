#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { isAbsolute, join, normalize, resolve } from "node:path";

import {
  assertPrincipalStoreSafe,
  loadPrincipalDeclaration,
  resolvePrincipalStore,
} from "../lib/principals.mjs";

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function warning(error) {
  const message = error instanceof Error ? error.message : String(error);
  output({ warning: `oas-aweb: ${message.slice(0, 400)}` });
}

function requiredAbsoluteDirectory(value, name) {
  if (!value || !isAbsolute(value)) throw new TypeError(`${name} must be an absolute path`);
  const path = normalize(resolve(value));
  if (realpathSync(path) !== path) throw new Error(`${name} must be canonical`);
  return path;
}

function parseAttachSettings() {
  let settings;
  try {
    settings = JSON.parse(process.env.OAS_SETTINGS || "{}");
  } catch {
    throw new TypeError("OAS_SETTINGS must be valid JSON");
  }
  const binding = settings?.identity_binding;
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new TypeError("identity_binding settings are required");
  }
  const fields = Object.keys(binding).sort();
  if (fields.join(",") !== "mode,principal,schema_version") {
    throw new TypeError("identity_binding must contain exactly schema_version, mode, and principal");
  }
  if (binding.schema_version !== 1) throw new TypeError("identity_binding.schema_version must be 1");
  if (binding.mode !== "attach") throw new TypeError("only attach mode is supported by this capability");
  if (typeof binding.principal !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(binding.principal)) {
    throw new TypeError("identity_binding.principal must be a declaration basename");
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

function attach() {
  const binding = parseAttachSettings();
  const instanceHome = requiredAbsoluteDirectory(process.env.OAS_HOME, "OAS_HOME");
  const context = requiredAbsoluteDirectory(process.env.OAS_CONTEXT, "OAS_CONTEXT");
  const soul = process.env.OAS_AGENT;
  if (!soul || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(soul)) {
    throw new TypeError("OAS_AGENT must be a filesystem-safe soul name");
  }

  const declarationFile = join(context, "oas", "agents", soul, "principals", `${binding.principal}.yaml`);
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
    throw new Error(`attached identity address ${JSON.stringify(whoami.address)} does not match declaration ${JSON.stringify(declaration.address)}`);
  }
  if (whoami.stable_id !== declaration.stable_id) {
    throw new Error(`attached identity stable_id ${JSON.stringify(whoami.stable_id)} does not match declaration ${JSON.stringify(declaration.stable_id)}`);
  }
  if (whoami.team_id !== undefined && whoami.team_id !== declaration.team_id) {
    throw new Error(`attached identity team_id ${JSON.stringify(whoami.team_id)} does not match declaration ${JSON.stringify(declaration.team_id)}`);
  }

  const identityBinding = {
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
  };
  output({
    meta: { identity_binding: identityBinding },
    brief: `Identity: attached to ${declaration.address} (${declaration.stable_id}); external cleanup ownership preserves the principal when this instance retires.`,
  });
}

function retire() {
  let metadata;
  try {
    metadata = JSON.parse(process.env.OAS_META || "{}");
  } catch {
    throw new TypeError("persisted OAS_META is invalid; no principal cleanup was attempted");
  }
  const binding = metadata?.identity_binding;
  if (!binding || binding.schema_version !== 1 || binding.mode !== "attach" || binding.cleanup_owner !== "external") {
    throw new Error("persisted external attach binding is missing or malformed; no principal cleanup was attempted");
  }
  output({
    meta: {
      identity_binding: binding,
      retirement: { action: "preserve_principal", cleanup_owner: "external" },
    },
  });
}

const event = process.env.OAS_EVENT || process.argv[2];
try {
  if (event === "spawn") attach();
  else if (event === "retire") retire();
  else throw new TypeError(`unsupported lifecycle event ${JSON.stringify(event)}`);
} catch (error) {
  warning(error);
}
