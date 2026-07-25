import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, test } from "node:test";

import {
  principalDeclarationSchema,
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

test("declarations require exactly the public identity contract", () => {
  for (const field of ["schema_version", "address", "stable_id", "team_id", "soul"]) {
    const invalid = declaration();
    delete invalid[field];
    assert.throws(() => validatePrincipalDeclaration(invalid), new RegExp(`missing required field: ${field}`));
  }

  assert.throws(() => validatePrincipalDeclaration(declaration({ schema_version: 2 })), /schema_version must be 1/);
  assert.throws(() => validatePrincipalDeclaration(declaration({ address: "not-an-address" })), /address/);
  assert.throws(() => validatePrincipalDeclaration(declaration({ address: "example.test\\..\\escape/name" })), /address/);
  for (const teamId of ["not-a-team-id", "a__b:c", "a:b__c", "team:..", "team:example.test\\..\\escape"]) {
    assert.throws(() => validatePrincipalDeclaration(declaration({ team_id: teamId })), /team_id/);
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
