#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url);
const distPath = join(root.pathname, "dist", "index.js");
const packagePath = join(root.pathname, "package.json");
const pluginPath = join(root.pathname, ".claude-plugin", "plugin.json");

let selectedDistPath = distPath;
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] !== "--dist" || !process.argv[index + 1]) {
    throw new Error("usage: check-package-dist.mjs [--dist PATH]");
  }
  selectedDistPath = process.argv[index + 1];
  index += 1;
}

const dist = readFileSync(selectedDistPath, "utf8");
const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
const plugin = JSON.parse(readFileSync(pluginPath, "utf8"));

const certificateFirst = "const stableID = certificateStableID || identityStableID";
const staleIdentityFirst = "const stableID = (identity?.stable_id || \"\").trim() || (certificate.member_did_aw || \"\").trim()";
const appEventConsumer = 'case "app_event"';
const appAwakeningKind = 'kind: "app"';
const authenticatedTrustCodeMarkers = [
  "msg.encrypted_envelope != null",
  "msg.subject = decrypted.subject",
  "msg.body = decrypted.body",
  '["--team", options.teamID.trim()]',
  "is missing certificate signing authentication",
];
const unsafeDecryptMerge = "Object.assign(msg, decrypted)";

// Freshness gate: the plugin bundle inlines channel-core via the file: symlink,
// so a stale channel-core/dist would silently ship the plugin WITHOUT the
// hardened security surface. Two independent checks guard this:
//
//  1. Fix-specific code markers below assert that the actual hardened code is
//     bundled. Each string exists only while its fix is present, so a revert of
//     the verifier or pin store (even one that keeps contract.ts) removes the
//     string and fails the gate. These prove code presence, not a declared
//     version.
//  2. The security-contract sentinel is a stable exported constant re-exported
//     by channel/src/index.ts. It changes only on an intentional contract
//     revision, so it flags an unbuilt/stale bundle without churning on
//     unrelated error-wording edits. It declares the contract version; it does
//     not by itself prove the code is present — that is what the markers do.
const securityCodeMarkers = [
  // aajc.3 DID-log verifier: genesis/rotation state_hash binding.
  "stableIdentityStateHash",
  // aajc.3 DID-log verifier: rotation-operation authorization enforcement.
  "seq>1 requires rotate_key operation",
  // aajc.3 DID-log verifier: did:aw must be the canonical derivation of the
  // genesis key, so a forged head cannot claim an unrelated identity.
  "did:aw not derived from genesis key",
  // aajr DID-log verifier: full-log walk anchoring the head to genesis.
  "verifyStableIdentityViaFullLog",
  // aajc.2 fail-closed trust pin store: present-but-empty rejects instead of
  // silently starting with a discarded store.
  "pin store is empty or has no document",
];
const securityContractSentinel =
  "aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1";

function validatePackageDist(candidate) {
  if (pkg.version !== plugin.version) {
    throw new Error(`plugin version ${plugin.version} does not match package version ${pkg.version}`);
  }
  if (!candidate.includes(certificateFirst)) {
    throw new Error(`channel dist is missing certificate-first stable_id resolution: ${certificateFirst}`);
  }
  if (candidate.includes(staleIdentityFirst)) {
    throw new Error("channel dist still contains stale identity.yaml-first stable_id resolution");
  }
  if (!candidate.includes(appEventConsumer) || !candidate.includes(appAwakeningKind)) {
    throw new Error("channel dist is missing bundled app_event consumer wake dispatch");
  }
  for (const marker of authenticatedTrustCodeMarkers) {
    if (!candidate.includes(marker)) {
      throw new Error(
        `channel dist is missing authenticated trust-boundary behavior (marker: ${JSON.stringify(marker)})`,
      );
    }
  }
  if (candidate.includes(unsafeDecryptMerge)) {
    throw new Error("channel dist permits decrypted child output to overwrite trust fields");
  }
  for (const marker of securityCodeMarkers) {
    if (!candidate.includes(marker)) {
      throw new Error(
        `channel dist is missing hardened security code (marker: ${JSON.stringify(marker)}) — channel-core was bundled stale or a security fix was reverted. Rebuild channel-core from source; if the code intentionally changed, update this marker.`,
      );
    }
  }
  if (!candidate.includes(securityContractSentinel)) {
    throw new Error(
      `channel dist is missing the channel-core security-contract sentinel (${securityContractSentinel}) — channel-core was bundled stale, or the contract changed without updating this gate. Rebuild channel-core; if the contract intentionally changed, update both channel-core/src/contract.ts and this sentinel.`,
    );
  }
}

validatePackageDist(dist);
console.log(`channel package dist is coherent for ${pkg.version}`);
