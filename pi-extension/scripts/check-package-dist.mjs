#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url);
const distPath = join(root.pathname, "dist", "index.js");
const dist = readFileSync(distPath, "utf8");

const certificateFirst = "const stableID = certificateStableID || identityStableID";
const staleIdentityFirst = "const stableID = (identity?.stable_id || \"\").trim() || (certificate.member_did_aw || \"\").trim()";

if (!dist.includes(certificateFirst)) {
  throw new Error(`pi-extension dist is missing certificate-first stable_id resolution: ${certificateFirst}`);
}

if (dist.includes(staleIdentityFirst)) {
  throw new Error("pi-extension dist still contains stale identity.yaml-first stable_id resolution");
}

console.log("pi-extension package dist uses certificate-first stable_id resolution");
