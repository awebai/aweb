#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url);
const distPath = join(root.pathname, "dist", "index.js");
let selectedDistPath = distPath;
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] !== "--dist" || !process.argv[index + 1]) {
    throw new Error("usage: check-package-dist.mjs [--dist PATH]");
  }
  selectedDistPath = process.argv[index + 1];
  index += 1;
}

const dist = readFileSync(selectedDistPath, "utf8");

const certificateFirst = "const stableID = certificateStableID || identityStableID";
const staleIdentityFirst = "const stableID = (identity?.stable_id || \"\").trim() || (certificate.member_did_aw || \"\").trim()";
const appEventConsumer = 'case "app_event"';
const appAwakeningKind = 'kind: "app"';

function validatePackageDist(candidate) {
  if (!candidate.includes(certificateFirst)) {
    throw new Error(`pi-extension dist is missing certificate-first stable_id resolution: ${certificateFirst}`);
  }
  if (candidate.includes(staleIdentityFirst)) {
    throw new Error("pi-extension dist still contains stale identity.yaml-first stable_id resolution");
  }
  if (!candidate.includes(appEventConsumer) || !candidate.includes(appAwakeningKind)) {
    throw new Error("pi-extension dist is missing bundled app_event consumer wake dispatch");
  }
}

validatePackageDist(dist);
console.log("pi-extension package dist uses certificate-first stable_id resolution and app_event wake dispatch");
