// Building a runtime's activity emitter from its loaded channel config: the
// signer must be the key that signs requests (docs/agent-activity.md,
// "The signed event": from_did is the agent's key, or the grant session key).
import { describe, expect, test } from "vitest";
import * as ed from "@noble/ed25519";
import type { AgentConfig } from "../src/config.js";
import { activitySigner } from "../src/activity/runtime.js";
import { computeDIDKey } from "../src/identity/did.js";

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
