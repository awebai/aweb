import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { resolveConfig } from "../src/config.js";
import {
  createShadowedPrincipalFixture,
  writeSigningKey,
  writeTeamCertificate,
  writeTeamState,
  writeWorkspaceBinding,
} from "./helpers/config_fixture.js";

describe("resolveConfig", () => {
  const originalIdentityHome = process.env.AWEB_IDENTITY_HOME;

  beforeEach(() => {
    delete process.env.AWEB_IDENTITY_HOME;
  });

  afterEach(() => {
    if (originalIdentityHome === undefined) {
      delete process.env.AWEB_IDENTITY_HOME;
    } else {
      process.env.AWEB_IDENTITY_HOME = originalIdentityHome;
    }
  });

  test("keeps resolving the working directory when AWEB_IDENTITY_HOME is unset", async () => {
    const { external, shadow, workdir } = await createShadowedPrincipalFixture();
    delete process.env.AWEB_IDENTITY_HOME;

    const config = await resolveConfig(workdir);

    expect(config.alias).toBe(shadow.alias);
    expect(config.did).toBe(shadow.did);
    expect(config.signingKey).toEqual(shadow.seed);
    expect(config.alias).not.toBe(external.alias);
  });

  test("resolves every identity resource from AWEB_IDENTITY_HOME instead of a valid working-directory shadow", async () => {
    const { external, shadow, workdir } = await createShadowedPrincipalFixture();
    process.env.AWEB_IDENTITY_HOME = external.identityHome;

    const config = await resolveConfig(workdir);

    expect(config.alias).toBe(external.alias);
    expect(config.teamID).toBe(external.teamID);
    expect(config.did).toBe(external.did);
    expect(config.signingKey).toEqual(external.seed);
    expect(config.did).not.toBe(shadow.did);
  });

  test("keeps tolerating a symlinked working-directory .aw when the external selector is unset", async () => {
    const { external } = await createShadowedPrincipalFixture();
    const workdir = join(dirname(external.identityHome), "default-symlink-instance");
    mkdirSync(workdir);
    symlinkSync(external.identityHome, join(workdir, ".aw"), "dir");
    delete process.env.AWEB_IDENTITY_HOME;

    const config = await resolveConfig(workdir);

    expect(config.alias).toBe(external.alias);
    expect(config.signingKey).toEqual(external.seed);
  });

  test("rejects a relative external identity home", async () => {
    const { workdir } = await createShadowedPrincipalFixture();
    process.env.AWEB_IDENTITY_HOME = "relative-principal-home";

    await expect(resolveConfig(workdir)).rejects.toThrow("AWEB_IDENTITY_HOME must be an absolute path");
  });

  test("rejects a symlinked external identity home", async () => {
    const { external, workdir } = await createShadowedPrincipalFixture();
    const linkedHome = join(dirname(external.identityHome), "linked-principal-home");
    symlinkSync(external.identityHome, linkedHome, "dir");
    process.env.AWEB_IDENTITY_HOME = linkedHome;

    await expect(resolveConfig(workdir)).rejects.toThrow(/identity home .* must not be a symlink/);
  });

  test.each([
    ["workspace config", "workspace.yaml"],
    ["team state", "teams.yaml"],
    ["identity config", "identity.yaml"],
    ["signing key", "signing.key"],
  ])("rejects a symlinked external %s before reading it", async (label, filename) => {
    const { external, workdir } = await createShadowedPrincipalFixture();
    const selectedPath = join(external.identityHome, filename);
    const movedPath = join(dirname(external.identityHome), `moved-${filename}`);
    renameSync(selectedPath, movedPath);
    symlinkSync(movedPath, selectedPath);
    process.env.AWEB_IDENTITY_HOME = external.identityHome;

    await expect(resolveConfig(workdir)).rejects.toThrow(
      new RegExp(`${label} .* must not be a symlink`),
    );
  });

  test("rejects a symlinked external team certificate before reading it", async () => {
    const { external, workdir } = await createShadowedPrincipalFixture();
    const certsDir = join(external.identityHome, "team-certs");
    const certificatePath = join(certsDir, readdirSync(certsDir)[0]);
    const movedCertificatePath = join(dirname(external.identityHome), "moved-certificate.pem");
    renameSync(certificatePath, movedCertificatePath);
    symlinkSync(movedCertificatePath, certificatePath);
    process.env.AWEB_IDENTITY_HOME = external.identityHome;

    await expect(resolveConfig(workdir)).rejects.toThrow(/team certificate .* must not be a symlink/);
  });

  test("rejects an external stored certificate path that escapes the identity home", async () => {
    const { external, workdir } = await createShadowedPrincipalFixture();
    const certificate = readdirSync(join(external.identityHome, "team-certs"))[0];
    copyFileSync(
      join(external.identityHome, "team-certs", certificate),
      join(dirname(external.identityHome), "outside.pem"),
    );
    for (const filename of ["workspace.yaml", "teams.yaml"]) {
      const path = join(external.identityHome, filename);
      writeFileSync(path, readFileSync(path, "utf8").replace(/cert_path: .*/g, "cert_path: ../outside.pem"));
    }
    process.env.AWEB_IDENTITY_HOME = external.identityHome;

    await expect(resolveConfig(workdir)).rejects.toThrow(/certificate path escapes AWEB_IDENTITY_HOME/);
  });

  test("loads channel config when workspace omits active_team and teams.yaml selects the team", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(7);
    const stableID = "did:aw:test";
    const address = "acme.com/support";
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "support",
      member_did_aw: stableID,
      member_address: address,
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "support", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "support", "team-certs/backend__acme.com.pem");
    writeFileSync(join(awDir, "identity.yaml"), [
      `did: ${did}`,
      `stable_id: ${stableID}`,
      `address: ${address}`,
      "registry_url: https://registry.example.test",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config.baseURL).toBe("https://app.aweb.ai");
    expect(config.teamID).toBe("backend:acme.com");
    expect(config.alias).toBe("support");
    expect(config.did).toBe(did);
    expect(config.stableID).toBe(stableID);
    expect(config.address).toBe(address);
    expect(config.registryURL).toBe("https://registry.example.test");
    expect(config.signingKey).toEqual(seed);
    expect(config.teamCertificateHeader).toBeTruthy();
  });

  test("prefers certificate stable_id over identity.yaml when both are present", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(23);
    const certificateStableID = "did:aw:cert";
    const identityStableID = "did:aw:stale";
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "alice",
      member_did_aw: certificateStableID,
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeFileSync(join(awDir, "identity.yaml"), [
      `did: ${did}`,
      `stable_id: ${identityStableID}`,
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config.stableID).toBe(certificateStableID);
  });

  test("ignores stray active_team in workspace.yaml and uses teams.yaml as source of truth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(19);
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "ops__acme.com.pem"), seed, {
      team_id: "ops:acme.com",
      alias: "ops-alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeFileSync(join(awDir, "workspace.yaml"), [
      "aweb_url: https://app.aweb.ai",
      "active_team: backend:acme.com",
      "memberships:",
      "  - team_id: backend:acme.com",
      "    alias: backend-alice",
      "    cert_path: team-certs/backend__acme.com.pem",
      "  - team_id: ops:acme.com",
      "    alias: ops-alice",
      "    cert_path: team-certs/ops__acme.com.pem",
      "",
    ].join("\n"));
    writeTeamState(awDir, "ops:acme.com", "ops-alice", "team-certs/ops__acme.com.pem");

    const config = await resolveConfig(dir);
    expect(config.teamID).toBe("ops:acme.com");
    expect(config.alias).toBe("ops-alice");
    expect(config.did).toBe(did);
  });

  test("prefers active team certificate member_address over identity address", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(13);
    const stableID = "did:aw:amy";
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__aweb.ai.pem"), seed, {
      team_id: "backend:aweb.ai",
      alias: "amy",
      member_did_aw: stableID,
      member_address: "aweb.ai/amy",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:aweb.ai", "amy", "team-certs/backend__aweb.ai.pem");
    writeTeamState(awDir, "backend:aweb.ai", "amy", "team-certs/backend__aweb.ai.pem");
    writeFileSync(join(awDir, "identity.yaml"), [
      `did: ${did}`,
      `stable_id: ${stableID}`,
      "address: juan.aweb.ai/amy",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config.address).toBe("aweb.ai/amy");
  });

  test("derives identity from team certificate when identity.yaml is absent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(9);
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    const config = await resolveConfig(dir);
    expect(config.baseURL).toBe("https://app.aweb.ai");
    expect(config.teamID).toBe("backend:acme.com");
    expect(config.alias).toBe("alice");
    expect(config.did).toBe(did);
    expect(config.stableID).toBe("");
    expect(config.address).toBe("");
    expect(config.registryURL).toBe("");
  });

  test("errors clearly when the team-certs directory is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });
    const seed = new Uint8Array(32).fill(11);
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    await expect(resolveConfig(dir)).rejects.toThrow(/migrate-multi-team/);
  });

  test("errors clearly when teams.yaml is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(17);
    await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);
    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    await expect(resolveConfig(dir)).rejects.toThrow(/teams\.yaml/);
  });

  test("errors clearly on the legacy single-team workspace shape", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });

    writeFileSync(join(awDir, "workspace.yaml"), [
      "aweb_url: http://localhost:8000",
      "team_address: acme.com/backend",
      "alias: alice",
      "",
    ].join("\n"));

    await expect(resolveConfig(dir)).rejects.toThrow(/migrate-multi-team/);
  });
});
