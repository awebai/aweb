// Building a runtime's activity emitter from its loaded channel config: the
// signer must be the key that signs requests (docs/agent-activity.md,
// "The signed event": from_did is the agent's key, or the grant session key).
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import type { APIClient } from "../src/api/client.js";
import { resolveConfig, type AgentConfig } from "../src/config.js";
import { activitySigner, createActivityEmitter } from "../src/activity/runtime.js";
import { computeDIDKey } from "../src/identity/did.js";
import { writeSigningKey } from "./helpers/config_fixture.js";

const KEY = Uint8Array.from(Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"));
const KEY_DID = computeDIDKey(ed.getPublicKey(KEY));

function config(extra: Partial<AgentConfig>): AgentConfig {
  return {
    identityHome: "/home/agent/.aw",
    baseURL: "https://app.aweb.ai",
    did: KEY_DID,
    stableID: "did:aw:agent",
    address: "acme.aweb.ai/agent",
    alias: "agent",
    teamID: "default:acme.aweb.ai",
    registryURL: "https://api.awid.ai",
    signingKey: KEY,
    teamCertificateHeader: "certificate",
    ...extra,
  };
}

describe("activitySigner", () => {
  test("a team-certificate runtime signs as its own key", () => {
    expect(activitySigner(config({}))).toEqual({
      did: KEY_DID, stableID: "did:aw:agent", teamID: "default:acme.aweb.ai", seed: KEY,
    });
  });

  test("a grant seat signs as the grant session key, attributed to its subject", () => {
    const signer = activitySigner(config({
      authMode: "grant",
      did: "did:key:z6MkSubjectKeyNotTheSigner",
      grantSessionDID: KEY_DID,
      grantID: "99999999-9999-4999-8999-999999999999",
    }));
    expect(signer.did).toBe(KEY_DID);
    expect(signer.stableID).toBe("did:aw:agent");
    expect(signer.seed).toBe(KEY);
  });

  test("a grant seat without its session DID cannot publish", () => {
    expect(() => activitySigner(config({ authMode: "grant", grantSessionDID: undefined })))
      .toThrow(/grant session/);
  });

  test("an identity without a stable id has none on its events", () => {
    expect(activitySigner(config({ stableID: "" })).stableID).toBeUndefined();
  });
});

describe("a grant seat's opt-in root", () => {
  // docs/agent-activity.md, "Host-owner opt-in": for a grant seat the file
  // lives in the grant home, which the running emitter loads; the resident
  // custody home never carries it.
  async function grantSeat(optInHome: "subject" | "grant") {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "activity-grant-seat-")));
    const subjectHome = join(dir, ".aw");
    const grantHome = join(dir, "grant.aw");
    mkdirSync(subjectHome, { recursive: true });
    mkdirSync(grantHome, { recursive: true });
    writeSigningKey(join(grantHome, "grant-signing.key"), KEY);
    writeFileSync(join(grantHome, "grant.yaml"), [
      "version: 1",
      "grant_id: 99999999-9999-4999-8999-999999999999",
      "team_id: default:acme.aweb.ai",
      "subject:",
      "  did_aw: did:aw:agent",
      "  did_key: did:key:z6MkSubjectKeyNotTheSigner",
      "  alias: agent",
      "scopes:",
      "  - chat.send",
      "expires_at: 2099-01-01T00:00:00Z",
      "aweb_url: https://app.aweb.ai",
      "",
    ].join("\n"));
    writeFileSync(join(optInHome === "subject" ? subjectHome : grantHome, "activity.yaml"), "activity: status\n");
    const config = await resolveConfig(dir, { identityHome: grantHome, teamID: "default:acme.aweb.ai" });
    const postAccepted = vi.fn(async () => undefined);
    const emitter = createActivityEmitter(config, { postAccepted } as unknown as APIClient);
    emitter.turnStarted();
    emitter.turnEnded();
    await emitter.drained();
    rmSync(dir, { recursive: true, force: true });
    return { config, grantHome, postAccepted };
  }

  test("is the grant home", async () => {
    const { config, grantHome } = await grantSeat("grant");
    expect(config.identityHome).toBe(grantHome);
  });

  test("an opt-in only in the subject's home leaves the grant seat off", async () => {
    const { postAccepted } = await grantSeat("subject");
    expect(postAccepted).not.toHaveBeenCalled();
  });

  test("an opt-in in the grant home turns it on, signed by the grant session key", async () => {
    const { postAccepted } = await grantSeat("grant");
    expect(postAccepted).toHaveBeenCalledTimes(2);
    const [, body] = postAccepted.mock.calls[0] as unknown as [string, { signed_payload: string }];
    const event = JSON.parse(Buffer.from(body.signed_payload, "base64url").toString("utf8"));
    expect(event.from_did).toBe(KEY_DID);
    expect(event.from_stable_id).toBe("did:aw:agent");
  });
});

