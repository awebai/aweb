import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { afterEach, test } from "node:test";

import {
  assertPrincipalStoreContained,
  loadPrincipalDeclaration,
  parsePrincipalDeclarationYaml,
  localPrincipalDeclarationSchema,
  principalDeclarationSchema,
  principalDeclarationSchemaFor,
  resolvePrincipalHome,
  resolvePrincipalStore,
  validatePrincipalDeclaration,
} from "../lib/principals.mjs";

const temporaryDirectories = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "aweb-principals-")));
  temporaryDirectories.push(directory);
  return directory;
}

function declaration(overrides = {}) {
  return {
    schema_version: 1,
    address: "example.test/throwaway",
    stable_id: "did:aw:2ThrowawayStableId123",
    team_id: "test-team:example.test",
    soul: "developer",
    ...overrides,
  };
}

test("the declaration schema pins a stable did:aw, never a rotatable did:key", () => {
  assert.equal(principalDeclarationSchema.properties.stable_id.pattern, "^did:aw:[A-Za-z0-9]+$");
  assert.throws(
    () => validatePrincipalDeclaration(declaration({ stable_id: "did:key:z6MkRotatableKey" })),
    /stable_id must be a did:aw stable identity/,
  );
  assert.deepEqual(validatePrincipalDeclaration(declaration()), declaration());
});

test("declaration YAML loading accepts only top-level scalar fields and rejects links", () => {
  const yaml = [
    "schema_version: 1",
    "address: example.test/throwaway # expected address",
    "stable_id: 'did:aw:2ThrowawayStableId123'",
    "team_id: test-team:example.test",
    "soul: \"developer\"",
    "",
  ].join("\n");
  assert.deepEqual(parsePrincipalDeclarationYaml(yaml), declaration());
  assert.throws(() => parsePrincipalDeclarationYaml(`${yaml}soul: duplicate\n`), /duplicate field: soul/);
  assert.throws(() => parsePrincipalDeclarationYaml(`${yaml}  nested: forbidden\n`), /top-level scalar/);

  const root = temporaryDirectory();
  const declarationPath = join(root, "throwaway.yaml");
  writeFileSync(declarationPath, yaml);
  assert.deepEqual(loadPrincipalDeclaration(declarationPath), {
    declaration: declaration(),
    path: declarationPath,
  });
  const linkedPath = join(root, "linked.yaml");
  symlinkSync(declarationPath, linkedPath);
  assert.throws(() => loadPrincipalDeclaration(linkedPath), /symbolic link/);
});

test("declarations require exactly the public identity contract", () => {
  for (const field of ["schema_version", "address", "stable_id", "team_id", "soul"]) {
    const invalid = declaration();
    delete invalid[field];
    assert.throws(() => validatePrincipalDeclaration(invalid), new RegExp(`missing required field: ${field}`));
  }

  assert.throws(() => validatePrincipalDeclaration(declaration({ schema_version: 2 })), /schema_version must be 1/);
  assert.throws(() => validatePrincipalDeclaration(declaration({ address: "not-an-address" })), /address/);
  assert.throws(() => validatePrincipalDeclaration(declaration({ address: "example.test\\..\\escape/name" })), /address/);
  for (const teamId of [
    "not-a-team-id",
    "a__b:c",
    "a:b__c",
    "team:..",
    "team:example.test\\..\\escape",
    "Test-Team:Example.Test",
    "test-team:example.test.",
  ]) {
    assert.throws(
      () => validatePrincipalDeclaration(declaration({ team_id: teamId })),
      /canonical lowercase DNS-style team-name:namespace/,
    );
  }
  assert.throws(() => validatePrincipalDeclaration(declaration({ soul: "" })), /soul/);
  assert.throws(() => validatePrincipalDeclaration({ ...declaration(), signing_key: "secret" }), /unknown field: signing_key/);

  const versioned = declaration({ soul_version: "1.2.3" });
  assert.deepEqual(validatePrincipalDeclaration(versioned), versioned);
});

test("principal home resolution follows explicit, environment, platform, fallback precedence", () => {
  const root = temporaryDirectory();
  const explicitHome = join(root, "explicit", "principals");
  const environmentHome = join(root, "environment", "principals");
  const xdgHome = join(root, "xdg", "data");
  const home = join(root, "home", "test");
  const options = {
    env: {
      AWEB_PRINCIPAL_HOME: environmentHome,
      XDG_DATA_HOME: xdgHome,
    },
    home,
    platform: "linux",
  };

  assert.equal(resolvePrincipalHome({ ...options, explicitHome }), explicitHome);
  assert.equal(resolvePrincipalHome(options), environmentHome);
  assert.equal(
    resolvePrincipalHome({ ...options, env: { XDG_DATA_HOME: xdgHome } }),
    join(xdgHome, "aweb", "principals"),
  );
  assert.equal(
    resolvePrincipalHome({ ...options, env: {} }),
    join(home, ".local", "share", "aweb", "principals"),
  );
  assert.equal(
    resolvePrincipalHome({ ...options, env: {}, platform: "darwin" }),
    join(home, "Library", "Application Support", "aweb", "principals"),
  );
  assert.equal(
    resolvePrincipalHome({ ...options, env: {}, platform: "aix" }),
    join(home, ".aweb", "principals"),
  );
});

test("principal home resolution never derives a relative path from cwd", () => {
  assert.throws(
    () => resolvePrincipalHome({ explicitHome: "relative/principals", env: {}, home: "/home/test", platform: "linux" }),
    /explicit principal home must be absolute/,
  );
  assert.throws(
    () => resolvePrincipalHome({ env: { AWEB_PRINCIPAL_HOME: "relative/principals" }, home: "/home/test", platform: "linux" }),
    /AWEB_PRINCIPAL_HOME must be absolute/,
  );
});

test("store paths use structural team identifiers and keep credentials and state as siblings", () => {
  const base = join(temporaryDirectory(), "not-created");
  const paths = resolvePrincipalStore(declaration(), { explicitHome: base, env: {} });

  assert.deepEqual(paths, {
    home: base,
    principal: join(base, "test-team", "example.test", "2ThrowawayStableId123"),
    credentials: join(base, "test-team", "example.test", "2ThrowawayStableId123", "credentials"),
    state: join(base, "test-team", "example.test", "2ThrowawayStableId123", "state"),
  });
  assert.equal(existsSync(base), false, "pure resolution must not create the principal store");
});

test("store resolution rejects a symlink in any existing path component", () => {
  const root = temporaryDirectory();
  const target = temporaryDirectory();
  const linkedHome = join(root, "linked-home");
  symlinkSync(target, linkedHome, "dir");

  assert.throws(
    () => resolvePrincipalHome({ explicitHome: linkedHome, env: {} }),
    /symbolic link/,
  );
  assert.throws(
    () => resolvePrincipalStore(declaration(), { explicitHome: linkedHome, env: {} }),
    /symbolic link/,
  );

  const home = join(root, "principals");
  mkdirSync(home);
  symlinkSync(target, join(home, "test-team"), "dir");
  assert.throws(
    () => resolvePrincipalStore(declaration(), { explicitHome: home, env: {} }),
    /symbolic link/,
  );
});

test("store resolution rejects links at principal, credentials, and state boundaries", () => {
  for (const component of ["principal", "credentials", "state"]) {
    const root = temporaryDirectory();
    const target = temporaryDirectory();
    const home = join(root, "principals");
    const principal = join(home, "test-team", "example.test", "2ThrowawayStableId123");
    const linkedPath = component === "principal" ? principal : join(principal, component);
    mkdirSync(dirname(linkedPath), { recursive: true });
    symlinkSync(target, linkedPath, "dir");

    assert.throws(
      () => resolvePrincipalStore(declaration(), { explicitHome: home, env: {} }),
      /symbolic link/,
      `${component} symlink must be rejected`,
    );
  }
});

test("store resolution rejects a dangling link rather than treating it as a missing path", () => {
  const root = temporaryDirectory();
  const home = join(root, "principals");
  const principal = join(home, "test-team", "example.test", "2ThrowawayStableId123");
  mkdirSync(principal, { recursive: true });
  symlinkSync(join(root, "missing-target"), join(principal, "credentials"), "dir");

  assert.throws(
    () => resolvePrincipalStore(declaration(), { explicitHome: home, env: {} }),
    /symbolic link/,
  );
});

test("containment rejects principal, credentials, and state independently", () => {
  const home = join(temporaryDirectory(), "principals");
  const principal = join(home, "test-team", "example.test", "2ThrowawayStableId123");
  const paths = {
    principal,
    credentials: join(principal, "credentials"),
    state: join(principal, "state"),
  };

  for (const field of ["principal", "credentials", "state"]) {
    assert.throws(
      () => assertPrincipalStoreContained(home, { ...paths, [field]: join(home, "..", `${field}-escape`) }),
      new RegExp(`${field} path escapes principal home`),
    );
  }
});

test("store resolution enforces containment after validation", () => {
  let teamIdReads = 0;
  const changingDeclaration = {
    ...declaration(),
    get team_id() {
      teamIdReads += 1;
      return teamIdReads <= 2 ? "test-team:example.test" : "test-team:../../../escape";
    },
  };

  assert.throws(
    () => resolvePrincipalStore(changingDeclaration, { explicitHome: join(temporaryDirectory(), "principals"), env: {} }),
    /escapes principal home/,
  );
});

// A durable TEAM-LOCAL member is a different shape, not a global with fields
// missing. Measured rather than assumed: a durable local carries a team
// membership and certificate and has no did:aw, and cold contact to one fails at
// recipient resolution with "Address not found" — so it has no address to carry.
const LOCAL = Object.freeze({
  schema_version: 2,
  scope: "local",
  member_name: "snape",
  team_id: "default:cjr.aweb.ai",
  soul: "accounting-reviewer",
});

test("a durable local principal is declarable without an address or a did:aw", () => {
  assert.deepEqual(validatePrincipalDeclaration({ ...LOCAL }), LOCAL);
  assert.deepEqual(
    validatePrincipalDeclaration({ ...LOCAL, soul_version: "1.2.3" }),
    { ...LOCAL, soul_version: "1.2.3" },
  );
});

test("a local declaration cannot carry global-only identity fields", () => {
  // These are the two fields a local does not have. Accepting either would let a
  // local be described as a degraded global and re-open the shape confusion.
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, address: "cjr.aweb.ai/snape" }), /unknown field: address/);
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, stable_id: "did:aw:2Abc" }), /unknown field: stable_id/);
});

test("the local shape is explicitly discriminated, never inferred from omission", () => {
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, schema_version: 1 }), /schema_version 2/);
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, scope: "global" }), /scope must be "local"/);
  for (const field of ["scope", "member_name", "team_id", "soul"]) {
    const partial = { ...LOCAL };
    delete partial[field];
    if (field === "scope") {
      // Dropping scope stops it being a local declaration at all: it becomes a
      // global one, which demands the global-only fields. The point is that a
      // local is never inferred from what is absent.
      assert.throws(() => validatePrincipalDeclaration(partial), /missing required field: address/);
    } else {
      assert.throws(() => validatePrincipalDeclaration(partial), new RegExp(`missing required field: ${field}`));
    }
  }
});

test("a local member name is exactly what the issuing authority can issue", () => {
  // Bounds taken from the issuer, not invented here: workspaceAliasPattern in
  // cli/go/cmd/aw/workspace.go and AGENT_ALIAS_PATTERN/MAX_LENGTH on the server.
  // Deriving them from the team-name pattern rejected names aw really issues.
  for (const good of ["snape", "Build_Bot", "a", "A1", "x-y_z", "a".repeat(64)]) {
    assert.deepEqual(validatePrincipalDeclaration({ ...LOCAL, member_name: good }).member_name, good);
  }
  for (const bad of ["-snape", "_snape", "a".repeat(65), "", "sn ape", "sn/ape"]) {
    assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, member_name: bad }), /member_name must match/);
  }
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, member_name: "me" }), /reserved alias/);
  assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, secret: "k" }), /unknown field: secret/);
});

test("a local resolves a principal store that cannot collide with a global one", () => {
  const home = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "aweb-oas-store-")));
  temporaryDirectories.push(home);
  const local = resolvePrincipalStore({ ...LOCAL }, { home });
  const global = resolvePrincipalStore({
    schema_version: 1, address: "e.test/x", stable_id: "did:aw:2Abc", team_id: "t:e.test", soul: "d",
  }, { home });
  // The crash this replaces: the store read declaration.stable_id unconditionally.
  assert.ok(local.principal.endsWith(join("members", LOCAL.member_name)), local.principal);
  assert.ok(!global.principal.includes(`${sep}members${sep}`), global.principal);
  assert.notEqual(local.principal, global.principal);
});

test("the global declaration is unchanged by the local shape", () => {
  const global = { schema_version: 1, address: "example.test/x", stable_id: "did:aw:2Abc", team_id: "t:example.test", soul: "dev" };
  assert.deepEqual(validatePrincipalDeclaration({ ...global }), global);
  for (const field of ["address", "stable_id"]) {
    const partial = { ...global };
    delete partial[field];
    assert.throws(() => validatePrincipalDeclaration(partial), new RegExp(`missing required field: ${field}`));
  }
});


test("a local store cannot contain, or be contained by, any global store on the same team", () => {
  const home = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "aweb-oas-store-")));
  temporaryDirectories.push(home);
  const local = resolvePrincipalStore({ ...LOCAL, team_id: "t:e.test" }, { home }).principal;
  // Adversarial: a did:aw whose id spells the separating component. A plain
  // "members" component made this global the exact PARENT of every local path.
  for (const id of ["localmembers", "localMembers", "snape", "members"]) {
    const global = resolvePrincipalStore({
      schema_version: 1, address: "e.test/x", stable_id: `did:aw:${id}`, team_id: "t:e.test", soul: "d",
    }, { home }).principal;
    assert.notEqual(local, global);
    assert.equal(local.startsWith(global + sep), false, `local nested under global for did:aw:${id}`);
    assert.equal(global.startsWith(local + sep), false, `global nested under local for did:aw:${id}`);
  }
});

test("the reserved member name follows the issuing authority, which compares case-insensitively", () => {
  for (const reserved of ["me", "ME", "Me", "mE"]) {
    assert.throws(() => validatePrincipalDeclaration({ ...LOCAL, member_name: reserved }), /reserved alias/);
  }
});

test("the exported schema selector follows the same discriminator as the validator", () => {
  const global = { schema_version: 1, address: "e.test/x", stable_id: "did:aw:2Abc", team_id: "t:e.test", soul: "d" };
  assert.equal(principalDeclarationSchemaFor(LOCAL), localPrincipalDeclarationSchema);
  assert.equal(principalDeclarationSchemaFor(global), principalDeclarationSchema);
  assert.equal(principalDeclarationSchemaFor(undefined), principalDeclarationSchema);
  // The v1 $id contract must not move when a second shape is added.
  assert.match(principalDeclarationSchema.$id, /principal-declaration-v1\.json$/);
  assert.equal(localPrincipalDeclarationSchema.required.includes("member_name"), true);
  assert.equal(localPrincipalDeclarationSchema.properties.address, undefined);
  assert.equal(localPrincipalDeclarationSchema.properties.stable_id, undefined);
});
