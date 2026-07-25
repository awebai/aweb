import { lstatSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, normalize, parse, relative, resolve, sep } from "node:path";

const REQUIRED_FIELDS = ["schema_version", "address", "stable_id", "team_id", "soul"];
const ALLOWED_FIELDS = new Set([...REQUIRED_FIELDS, "soul_version"]);
const STABLE_ID_PATTERN = "^did:aw:[A-Za-z0-9]+$";

export const principalDeclarationSchema = Object.freeze({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://aweb.ai/schemas/oas/principal-declaration-v1.json",
  title: "aweb OAS principal declaration",
  type: "object",
  additionalProperties: false,
  required: REQUIRED_FIELDS,
  properties: {
    schema_version: { type: "integer", const: 1 },
    address: { type: "string", pattern: "^[^\\s/]+/[^\\s/]+$" },
    stable_id: { type: "string", pattern: STABLE_ID_PATTERN },
    team_id: { type: "string", pattern: "^[^:\\s/]+:[^:\\s/]+$" },
    soul: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._-]*$" },
    soul_version: { type: "string", minLength: 1 },
  },
});

/** Validate an already-parsed principal declaration without loading its YAML source. */
export function validatePrincipalDeclaration(declaration) {
  if (!declaration || typeof declaration !== "object" || Array.isArray(declaration)) {
    throw new TypeError("principal declaration must be an object");
  }

  for (const field of REQUIRED_FIELDS) {
    if (!Object.hasOwn(declaration, field)) throw new TypeError(`missing required field: ${field}`);
  }
  for (const field of Object.keys(declaration)) {
    if (!ALLOWED_FIELDS.has(field)) throw new TypeError(`unknown field: ${field}`);
  }

  if (declaration.schema_version !== 1) throw new TypeError("schema_version must be 1");
  if (typeof declaration.address !== "string" || !/^[^\s/]+\/[^\s/]+$/.test(declaration.address)) {
    throw new TypeError("address must be a non-empty namespace/name address");
  }
  if (typeof declaration.stable_id !== "string" || !/^did:aw:[A-Za-z0-9]+$/.test(declaration.stable_id)) {
    throw new TypeError("stable_id must be a did:aw stable identity");
  }
  if (typeof declaration.team_id !== "string" || !/^[^:\s/]+:[^:\s/]+$/.test(declaration.team_id)) {
    throw new TypeError("team_id must be a non-empty team:namespace identifier");
  }
  if (typeof declaration.soul !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(declaration.soul)) {
    throw new TypeError("soul must be a non-empty filesystem-safe reference");
  }
  if (Object.hasOwn(declaration, "soul_version")
      && (typeof declaration.soul_version !== "string" || declaration.soul_version.length === 0)) {
    throw new TypeError("soul_version must be a non-empty string");
  }

  return declaration;
}

function absolutePath(value, source) {
  if (!isAbsolute(value)) throw new TypeError(`${source} must be absolute`);
  return normalize(resolve(value));
}

function checkedPrincipalHome(path) {
  assertNoExistingSymlink(path);
  return path;
}

/** Resolve the host-local principal-store root without consulting or writing cwd. */
export function resolvePrincipalHome({
  explicitHome,
  env = process.env,
  home = homedir(),
  platform = process.platform,
} = {}) {
  if (explicitHome) return checkedPrincipalHome(absolutePath(explicitHome, "explicit principal home"));
  if (env.AWEB_PRINCIPAL_HOME) {
    return checkedPrincipalHome(absolutePath(env.AWEB_PRINCIPAL_HOME, "AWEB_PRINCIPAL_HOME"));
  }

  let platformDataHome;
  if (platform === "darwin") {
    platformDataHome = join(absolutePath(home, "home directory"), "Library", "Application Support");
  } else if (platform === "linux") {
    platformDataHome = env.XDG_DATA_HOME
      ? absolutePath(env.XDG_DATA_HOME, "XDG_DATA_HOME")
      : join(absolutePath(home, "home directory"), ".local", "share");
  } else if (platform === "win32" && env.LOCALAPPDATA) {
    platformDataHome = absolutePath(env.LOCALAPPDATA, "LOCALAPPDATA");
  }

  const resolvedHome = platformDataHome
    ? normalize(join(platformDataHome, "aweb", "principals"))
    : normalize(join(absolutePath(home, "home directory"), ".aweb", "principals"));
  return checkedPrincipalHome(resolvedHome);
}

function assertNoExistingSymlink(path) {
  const root = parse(path).root;
  let current = root;
  for (const component of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, component);
    try {
      if (lstatSync(current).isSymbolicLink()) {
        throw new Error(`principal store path contains a symbolic link: ${current}`);
      }
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
  }
}

/** Resolve, but never create, the paths belonging to one validated principal. */
export function resolvePrincipalStore(declaration, options = {}) {
  validatePrincipalDeclaration(declaration);
  const home = resolvePrincipalHome(options);
  const teamDirectory = declaration.team_id.replaceAll(":", "__");
  const principalId = declaration.stable_id.slice("did:aw:".length);
  const principal = join(home, teamDirectory, principalId);
  const credentials = join(principal, "credentials");
  const state = join(principal, "state");

  assertNoExistingSymlink(credentials);
  assertNoExistingSymlink(state);

  return { home, principal, credentials, state };
}
