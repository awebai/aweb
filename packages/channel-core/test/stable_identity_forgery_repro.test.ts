import { describe, expect, test } from "vitest";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { computeDIDKey, computeStableID } from "../src/identity/did.js";
import {
  canonicalDidLogPayload,
  verifyDidKeyResolution,
  type DidKeyResolution,
} from "../src/identity/registry.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// aajc.3 repro: the TS DID-log verifier accepts a seq>1 rotation whose
// authorized_by / previous_did_key are attacker-held keys, never bound to the
// victim's genesis key. After the fix an unanchored seq>1 head MUST be
// OK_DEGRADED, never OK_VERIFIED.
describe("forged rotation spoofing (aajc.3 repro)", () => {
  test("forged rotation must not be accepted as OK_VERIFIED", () => {
    // Victim genesis key -> the did:aw the attacker wants to steal.
    const victimPub = ed.getPublicKey(seed(0x11));
    const victimStableID = computeStableID(victimPub);

    // Attacker keys, unrelated to the victim.
    const attackerPrevPriv = seed(0x22);
    const attackerPrevPub = ed.getPublicKey(attackerPrevPriv);
    const attackerNewPub = ed.getPublicKey(seed(0x33));
    const attackerPrevDID = computeDIDKey(attackerPrevPub);
    const attackerNewDID = computeDIDKey(attackerNewPub);

    const head = {
      authorized_by: attackerPrevDID,
      new_did_key: attackerNewDID,
      operation: "rotate_key",
      prev_entry_hash: "0".repeat(64),
      previous_did_key: attackerPrevDID,
      seq: 2,
      // Canonical state hash for the attacker's replacement key.
      state_hash: bytesToHex(
        sha256(
          new TextEncoder().encode(
            `{"current_did_key":"${attackerNewDID}","did_aw":"${victimStableID}"}`,
          ),
        ),
      ),
      timestamp: "2026-02-22T10:05:00Z",
    };

    const payload = canonicalDidLogPayload(victimStableID, {
      ...head,
      entry_hash: "",
      signature: "",
    });
    const entryHash = bytesToHex(sha256(new TextEncoder().encode(payload)));
    // Unpadded standard base64, matching Go's RawStdEncoding — the wire contract.
    // A padded signature is rejected by both runtimes (default-aajc.8).
    const signature = Buffer.from(
      ed.sign(new TextEncoder().encode(payload), attackerPrevPriv),
    ).toString("base64url").replace(/-/g, "+").replace(/_/g, "/");

    const resolution: DidKeyResolution = {
      did_aw: victimStableID,
      current_did_key: attackerNewDID,
      log_head: { ...head, entry_hash: entryHash, signature },
    };

    const result = verifyDidKeyResolution(resolution, undefined, Date.now());

    expect(result.outcome).not.toBe("OK_VERIFIED");
    expect(result.outcome).toBe("OK_DEGRADED");
  });

  test("fractional seq cannot skip cached-head adjacency", () => {
    const victimGenesisPub = ed.getPublicKey(seed(0x11));
    const victimGenesisDID = computeDIDKey(victimGenesisPub);
    const victimStableID = computeStableID(victimGenesisPub);

    const attackerPrevPriv = seed(0x22);
    const attackerPrevDID = computeDIDKey(ed.getPublicKey(attackerPrevPriv));
    const attackerNewDID = computeDIDKey(ed.getPublicKey(seed(0x33)));

    const head = {
      authorized_by: attackerPrevDID,
      new_did_key: attackerNewDID,
      operation: "rotate_key",
      prev_entry_hash: "0".repeat(64),
      previous_did_key: attackerPrevDID,
      seq: 1.5,
      state_hash: bytesToHex(sha256(new TextEncoder().encode(
        `{"current_did_key":"${attackerNewDID}","did_aw":"${victimStableID}"}`,
      ))),
      timestamp: "2026-02-22T10:05:00Z",
    };
    const payload = canonicalDidLogPayload(victimStableID, {
      ...head,
      entry_hash: "",
      signature: "",
    });
    const entryHash = bytesToHex(sha256(new TextEncoder().encode(payload)));
    const signature = Buffer.from(
      ed.sign(new TextEncoder().encode(payload), attackerPrevPriv),
    ).toString("base64url").replace(/-/g, "+").replace(/_/g, "/");

    const resolution: DidKeyResolution = {
      did_aw: victimStableID,
      current_did_key: attackerNewDID,
      log_head: { ...head, entry_hash: entryHash, signature },
    };
    const cached = {
      seq: 1,
      entryHash: "a".repeat(64),
      stateHash: "b".repeat(64),
      currentDidKey: victimGenesisDID,
      fetchedAt: 0,
    };

    const result = verifyDidKeyResolution(resolution, cached, Date.now());

    expect(result.outcome).toBe("HARD_ERROR");
    expect(result.nextHead).toBeUndefined();
  });
});
