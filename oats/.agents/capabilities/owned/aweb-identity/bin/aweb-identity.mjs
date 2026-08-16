#!/usr/bin/env node
/**
 * aweb.identity lifecycle hooks.
 *
 *   aweb-identity spawn    mint a session grant for the resident identity
 *   aweb-identity retire   revoke that grant
 *
 * The resident identity's root keys live in the custody `.aw` home and never
 * enter the instance. Spawn mints a scoped, expiring grant into
 * <instance-home>/.aweb-identity and points the launched process at it via
 * AWEB_IDENTITY_HOME, which `aw` honors natively. Every artifact the spawn
 * creates either expires by itself (the grant) or lives inside the instance
 * home (the grant credential), so there is no cleanup beyond revoke.
 *
 * The spawn hook is declared required: an instance told it has messaging when
 * no grant was minted would improvise, which is worse than not starting. So
 * every path that mints no grant exits nonzero.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

const GRANT_DIR = ".aweb-identity";
const DEFAULT_SCOPES = ["mail.read", "mail.send", "chat.read", "chat.send"];
const DEFAULT_TTL = "8h";

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function fatal(message) {
  process.stderr.write(`aweb.identity: ${message}\n`);
  process.exit(1);
}

function settings() {
  let parsed;
  try {
    parsed = JSON.parse(process.env.OATS_SETTINGS || "{}");
  } catch {
    fatal("OATS_SETTINGS is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fatal("OATS_SETTINGS must be an object");
  return parsed;
}

/** The custody root is the directory whose `.aw` holds the resident
 * identity's root keys. A relative setting resolves against OATS_WORKSPACE so
 * the committed config stays machine-independent. */
function custodyRoot(cfg) {
  const workspace = process.env.OATS_WORKSPACE || "";
  const declared = typeof cfg["custody-root"] === "string" && cfg["custody-root"] ? cfg["custody-root"] : ".";
  if (!workspace && !isAbsolute(declared)) fatal("no OATS_WORKSPACE and custody-root is relative, so the resident identity's home cannot be located");
  const root = isAbsolute(declared) ? declared : resolve(workspace, declared);
  if (!existsSync(join(root, ".aw", "identity.yaml"))) {
    fatal(`${join(root, ".aw")} is not an initialized identity home (no identity.yaml), so no grant can be minted — set the messaging capability's custody-root setting to the directory containing the resident identity's .aw`);
  }
  return root;
}

function grantScopes(cfg) {
  const declared = cfg.scopes;
  if (declared === undefined) return DEFAULT_SCOPES;
  if (!Array.isArray(declared) || !declared.length || !declared.every((s) => typeof s === "string" && s)) {
    fatal("the scopes setting must be a non-empty array of scope strings");
  }
  return declared;
}

function aw(root, args) {
  return execFileSync("aw", args, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60000,
    // The custody home is resolved from cwd; an inherited AWEB_IDENTITY_HOME
    // (e.g. this hook running inside another instance) must not redirect the
    // mint to a grant home, which cannot mint.
    env: { ...process.env, AWEB_IDENTITY_HOME: join(root, ".aw") },
  });
}

function parseLastJson(stdout) {
  const line = String(stdout).trim().split("\n").filter(Boolean).pop() || "{}";
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

function spawn() {
  const home = process.env.OATS_INSTANCE_HOME || process.env.OATS_HOME;
  const instance = process.env.OATS_INSTANCE;
  if (!home || !instance) fatal("OATS_INSTANCE_HOME/OATS_INSTANCE missing — not running under an OATS spawn");
  try {
    execFileSync("aw", ["--version"], { stdio: "ignore" });
  } catch {
    fatal("aw CLI not on PATH, so no grant can be minted and this instance would have no messaging — https://aweb.ai/docs");
  }
  const cfg = settings();
  const root = custodyRoot(cfg);
  const grantHome = join(home, GRANT_DIR);
  if (existsSync(grantHome)) fatal(`${grantHome} already exists; refusing to overwrite a credential directory`);

  const scopes = grantScopes(cfg);
  const ttl = typeof cfg.ttl === "string" && cfg.ttl ? cfg.ttl : DEFAULT_TTL;
  let minted;
  try {
    minted = parseLastJson(aw(root, [
      "id", "grant", "mint",
      "--scope", scopes.join(","),
      "--ttl", ttl,
      "--label", `oats:${instance}`,
      "--out", grantHome,
      "--json",
    ]));
  } catch (e) {
    const detail = String(e.stderr ?? e.message ?? "").trim();
    fatal(`aw id grant mint failed, so no grant was minted and this instance would have no messaging — ${detail || "unknown error"}`);
  }
  if (!minted || typeof minted.grant_id !== "string" || !minted.grant_id) {
    fatal("aw id grant mint returned no usable grant, so this instance would have no messaging");
  }

  const who = minted.address || minted.alias || "the resident identity";
  output({
    meta: {
      grant_id: minted.grant_id,
      expires_at: minted.expires_at,
      team_id: minted.team_id,
      alias: minted.alias,
      address: minted.address || null,
    },
    env: { AWEB_IDENTITY_HOME: grantHome },
    brief: `Comms: you act as ${who}${minted.team_id ? ` on team ${minted.team_id}` : ""} through a session grant (scopes: ${scopes.join(", ")}; expires ${minted.expires_at}). Use \`aw mail\` and \`aw chat\` normally; identity lifecycle commands are not yours to run.`,
  });
}

function retire() {
  let meta;
  try {
    meta = JSON.parse(process.env.OATS_META || "{}");
  } catch {
    meta = {};
  }
  const grantId = typeof meta.grant_id === "string" ? meta.grant_id : "";
  if (!grantId) {
    // Nothing was minted (or spawn failed before minting): nothing to revoke.
    output({ warning: "aweb.identity: no grant recorded for this instance; nothing to revoke" });
    return;
  }
  const root = custodyRoot(settings());
  try {
    aw(root, ["id", "grant", "revoke", grantId, "--json"]);
  } catch (e) {
    const detail = String(e.stderr ?? e.message ?? "").trim();
    // Revocation is the only cleanup this capability owes. The grant also
    // expires on its own TTL, so a failed revoke degrades to bounded exposure
    // rather than stranded state — but it is still a real failure to report.
    fatal(`aw id grant revoke ${grantId} failed: ${detail || "unknown error"} (the grant still expires at its TTL)`);
  }
  output({ meta: { revoked: grantId } });
}

const event = process.argv[2];
if (event === "spawn") spawn();
else if (event === "retire") retire();
else fatal(`unknown event ${JSON.stringify(event)} (expected spawn or retire)`);
