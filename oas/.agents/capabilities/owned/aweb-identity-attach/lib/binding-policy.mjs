import { createPublicKey, verify } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { isAbsolute, join, normalize, parse, relative, resolve, sep } from "node:path";

export const bindingModes = Object.freeze([
  "provision-disposable",
  "provision-durable",
  "attach-existing",
]);

const MODE_CLEANUP_OWNER = Object.freeze({
  "provision-disposable": "instance",
  "provision-durable": "external",
  "attach-existing": "external",
});
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DID_AW = /^did:aw:[A-Za-z0-9]+$/;

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
}

function canonicalAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && normalize(resolve(value)) === value;
}

export function cleanupOwnerForMode(mode) {
  const owner = MODE_CLEANUP_OWNER[mode];
  if (!owner) throw new TypeError(`unknown identity binding mode ${JSON.stringify(mode)}`);
  return owner;
}

export function validateBindingSettings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("identity_binding settings are required");
  }
  if (value.schema_version === 1) {
    if (!exactFields(value, ["schema_version", "mode", "principal"]) || value.mode !== "attach" || !SAFE_ID.test(value.principal)) {
      throw new TypeError("legacy identity_binding v1 must declare mode attach and a principal basename");
    }
    return { ...value, legacy: true };
  }
  if (value.schema_version !== 2) throw new TypeError("identity_binding.schema_version must be 1 or 2");
  if (!bindingModes.includes(value.mode)) throw new TypeError(`identity_binding.mode must be one of ${bindingModes.join(", ")}`);
  if (value.mode === "attach-existing") {
    if (!exactFields(value, ["schema_version", "mode", "principal"]) || !SAFE_ID.test(value.principal)) {
      throw new TypeError("attach-existing requires exactly schema_version, mode, and principal");
    }
  } else if (!exactFields(value, ["schema_version", "mode", "operation_id"]) || !SAFE_ID.test(value.operation_id)) {
    throw new TypeError(`${value.mode} requires exactly schema_version, mode, and operation_id (got ${Object.keys(value).sort().join(",")})`);
  }
  return { ...value, legacy: false };
}

export function pendingProvisionReceipt(settings) {
  const validated = settings?.legacy === false ? settings : validateBindingSettings(settings);
  if (!validated.mode.startsWith("provision-")) throw new TypeError("pending provisioning receipt requires a provision mode");
  return validateBindingReceipt({
    schema_version: 2,
    mode: validated.mode,
    lifecycle: "provision-pending",
    cleanup_owner: cleanupOwnerForMode(validated.mode),
    resource_identity: {
      kind: "provision-operation",
      operation_id: validated.operation_id,
      stable_id: null,
      reference: `operation:${validated.operation_id}`,
    },
    journal_operation: validated.operation_id,
  });
}

export function validateBindingReceipt(receipt) {
  const fields = ["schema_version", "mode", "lifecycle", "cleanup_owner", "resource_identity", "journal_operation"];
  if (!exactFields(receipt, fields) || receipt.schema_version !== 2 || !bindingModes.includes(receipt.mode)) {
    throw new TypeError("identity binding receipt has invalid schema or fields");
  }
  if (receipt.cleanup_owner !== cleanupOwnerForMode(receipt.mode)) {
    throw new TypeError("identity binding receipt contradicts mode cleanup ownership");
  }
  if (!exactFields(receipt.resource_identity, ["kind", "operation_id", "stable_id", "reference"])) {
    throw new TypeError("identity binding resource identity has invalid fields");
  }
  const resource = receipt.resource_identity;
  if (!SAFE_ID.test(receipt.journal_operation) || resource.operation_id !== receipt.journal_operation) {
    throw new TypeError("identity binding journal operation does not match its resource identity");
  }
  if (receipt.mode === "attach-existing") {
    if (receipt.lifecycle !== "bound" || receipt.cleanup_owner !== "external" || resource.kind !== "declared-principal"
        || !DID_AW.test(resource.stable_id) || !canonicalAbsolutePath(resource.reference)) {
      throw new TypeError("attach-existing receipt has a contradictory lifecycle or resource identity");
    }
  } else {
    if (!["provision-pending", "provisioned"].includes(receipt.lifecycle)) {
      throw new TypeError("provision receipt has a contradictory lifecycle or resource identity");
    }
    if (receipt.lifecycle === "provision-pending") {
      if (resource.kind !== "provision-operation" || resource.reference !== `operation:${resource.operation_id}` || resource.stable_id !== null) {
        throw new TypeError("pending provision receipt must name only its operation");
      }
    } else if (receipt.mode === "provision-durable") {
      if (resource.kind !== "declared-principal" || !DID_AW.test(resource.stable_id) || !canonicalAbsolutePath(resource.reference)) {
        throw new TypeError("durable provisioned receipt requires a locatable did:aw declaration");
      }
    } else if (resource.kind !== "provision-operation" || resource.reference !== `operation:${resource.operation_id}`
        || (resource.stable_id !== null && !DID_AW.test(resource.stable_id))) {
      throw new TypeError("disposable provisioned receipt has an invalid operation identity");
    }
  }
  return receipt;
}

export function attachmentReceipt({ declarationPath, stableID }) {
  if (!canonicalAbsolutePath(declarationPath) || !DID_AW.test(stableID)) {
    throw new TypeError("attach-existing receipt requires a canonical declaration and did:aw");
  }
  const operation = `attach-${stableID.slice("did:aw:".length)}`;
  if (!SAFE_ID.test(operation)) throw new TypeError("attach-existing operation identity is invalid");
  return validateBindingReceipt({
    schema_version: 2,
    mode: "attach-existing",
    lifecycle: "bound",
    cleanup_owner: "external",
    resource_identity: {
      kind: "declared-principal",
      operation_id: operation,
      stable_id: stableID,
      reference: declarationPath,
    },
    journal_operation: operation,
  });
}

export function cleanupJudgement(instanceReceipt, authorityRecord, instanceID) {
  let receipt;
  try {
    receipt = validateBindingReceipt(instanceReceipt);
  } catch {
    return { action: "preserve", cleanup_authorized: false, reason: "missing_or_invalid_instance_receipt" };
  }
  if (receipt.cleanup_owner !== "instance" || receipt.mode !== "provision-disposable" || receipt.lifecycle !== "provisioned") {
    return { action: "preserve", cleanup_authorized: false, reason: "instance_metadata_withholds_cleanup" };
  }
  if (!cleanupAuthorityMatches(authorityRecord, receipt, instanceID)) {
    return { action: "preserve", cleanup_authorized: false, reason: "capability_authority_missing_or_mismatched" };
  }
  return { action: "authorize_cleanup", cleanup_authorized: true, reason: "capability_evidence_matches_disposable_resource" };
}

function cleanupAuthorityMatches(authorityRecord, receipt, instanceID) {
  if (!exactFields(authorityRecord, ["schema_version", "instance_id", "receipt"])
      || authorityRecord.schema_version !== 1 || authorityRecord.instance_id !== instanceID) return false;
  try {
    return JSON.stringify(validateBindingReceipt(authorityRecord.receipt)) === JSON.stringify(receipt);
  } catch {
    return false;
  }
}

function assertNoSymlink(path) {
  const root = parse(path).root;
  let current = root;
  for (const component of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, component);
    if (!existsSync(current)) return;
    if (lstatSync(current).isSymbolicLink()) throw new Error(`binding authority path contains a symbolic link: ${current}`);
  }
}

export function cleanupAuthorityPayload({ schema_version: schemaVersion, instance_id: instanceID, receipt }) {
  return Buffer.from(JSON.stringify({ schema_version: schemaVersion, instance_id: instanceID, receipt }), "utf8");
}

export function loadCleanupAuthority(authorityHome, instanceID) {
  if (!canonicalAbsolutePath(authorityHome)) throw new TypeError("binding authority home must be canonical and absolute");
  if (!SAFE_ID.test(instanceID)) throw new TypeError("OAS_INSTANCE must be filesystem-safe");
  const path = join(authorityHome, `${instanceID}.json`);
  const publicKeyPath = join(authorityHome, "authority.pub");
  assertNoSymlink(path);
  assertNoSymlink(publicKeyPath);
  if (!existsSync(path) || !existsSync(publicKeyPath)) return null;
  const encoded = JSON.parse(readFileSync(path, "utf8"));
  if (!exactFields(encoded, ["schema_version", "instance_id", "receipt", "signature"]) || typeof encoded.signature !== "string") {
    throw new TypeError("binding authority record has invalid signed fields");
  }
  const record = { schema_version: encoded.schema_version, instance_id: encoded.instance_id, receipt: encoded.receipt };
  const publicKey = createPublicKey(readFileSync(publicKeyPath, "utf8"));
  const signature = Buffer.from(encoded.signature, "base64");
  if (!verify(null, cleanupAuthorityPayload(record), publicKey, signature)) {
    throw new Error("binding authority signature is invalid");
  }
  return record;
}
