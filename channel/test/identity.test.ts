import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { computeDIDKey, extractPublicKey, computeStableID } from "../src/identity/did.js";
import { canonicalJSON, signMessage, verifyMessage, type MessageEnvelope } from "../src/identity/signing.js";
import { PinStore, type PinResult } from "../src/identity/pinstore.js";
import { loadSigningKey } from "../src/identity/keys.js";

const vectors = JSON.parse(
  readFileSync(join(import.meta.dir, "vectors.json"), "utf-8"),
);

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

const seed = b64ToBytes(vectors.seed);
const publicKey = b64ToBytes(vectors.publicKey);

// --- DID ---

describe("did", () => {
  test("computeDIDKey matches Go output", () => {
    expect(computeDIDKey(publicKey)).toBe(vectors.did);
  });

  test("extractPublicKey round-trips", () => {
    const extracted = extractPublicKey(vectors.did);
    expect(Buffer.from(extracted).toString("base64")).toBe(
      Buffer.from(publicKey).toString("base64"),
    );
  });

  test("extractPublicKey rejects invalid prefix", () => {
    expect(() => extractPublicKey("did:web:example.com")).toThrow("missing prefix");
  });

  test("extractPublicKey rejects wrong multicodec", () => {
    // Valid base58 but wrong header bytes
    expect(() => extractPublicKey("did:key:z111111111111111111111111111111111111111111111")).toThrow();
  });

  test("computeStableID matches Go output", () => {
    expect(computeStableID(publicKey)).toBe(vectors.stableID);
  });
});

// --- Signing ---

describe("canonicalJSON", () => {
  for (const vec of vectors.vectors) {
    test(`matches Go output: ${vec.name}`, () => {
      const result = canonicalJSON(vec.envelope as MessageEnvelope);
      expect(result).toBe(vec.canonical);
    });
  }
});

describe("signMessage", () => {
  for (const vec of vectors.vectors) {
    test(`produces correct signature: ${vec.name}`, async () => {
      const sig = await signMessage(seed, vec.envelope as MessageEnvelope);
      expect(sig).toBe(vec.signature);
    });
  }
});

describe("verifyMessage", () => {
  for (const vec of vectors.vectors) {
    test(`verifies valid signature: ${vec.name}`, async () => {
      const envelope: MessageEnvelope = {
        ...vec.envelope,
        signature: vec.signature,
        signing_key_id: vec.envelope.from_did,
      };
      const status = await verifyMessage(envelope);
      expect(status).toBe("verified");
    });
  }

  test("returns unverified when no DID", async () => {
    const envelope: MessageEnvelope = {
      from: "alice", from_did: "", to: "bob", to_did: "",
      type: "mail", subject: "", body: "", timestamp: "",
      signature: "something",
    };
    expect(await verifyMessage(envelope)).toBe("unverified");
  });

  test("returns unverified when no signature", async () => {
    const envelope: MessageEnvelope = {
      from: "alice", from_did: vectors.did, to: "bob", to_did: "",
      type: "mail", subject: "", body: "", timestamp: "",
      signature: "",
    };
    expect(await verifyMessage(envelope)).toBe("unverified");
  });

  test("returns failed for tampered body", async () => {
    const vec = vectors.vectors[0];
    const envelope: MessageEnvelope = {
      ...vec.envelope,
      body: "TAMPERED",
      signature: vec.signature,
      signing_key_id: vec.envelope.from_did,
    };
    const status = await verifyMessage(envelope);
    expect(status).toBe("failed");
  });

  test("returns failed when signing_key_id mismatches from_did", async () => {
    const vec = vectors.vectors[0];
    const envelope: MessageEnvelope = {
      ...vec.envelope,
      signature: vec.signature,
      signing_key_id: "did:key:zWRONG",
    };
    const status = await verifyMessage(envelope);
    expect(status).toBe("failed");
  });

  test("returns unverified for non-did:key DID", async () => {
    const envelope: MessageEnvelope = {
      from: "alice", from_did: "did:web:example.com", to: "bob", to_did: "",
      type: "mail", subject: "", body: "", timestamp: "",
      signature: "something",
    };
    expect(await verifyMessage(envelope)).toBe("unverified");
  });
});

// --- PinStore ---

describe("PinStore", () => {
  test("new store returns 'new' for unknown address", () => {
    const store = new PinStore();
    expect(store.checkPin("alice", vectors.did, "persistent")).toBe("new");
  });

  test("returns 'skipped' for ephemeral agents", () => {
    const store = new PinStore();
    expect(store.checkPin("alice", vectors.did, "ephemeral")).toBe("skipped");
  });

  test("returns 'ok' after storing pin", () => {
    const store = new PinStore();
    store.storePin(vectors.did, "alice", "", "");
    expect(store.checkPin("alice", vectors.did, "persistent")).toBe("ok");
  });

  test("returns 'mismatch' for different DID", () => {
    const store = new PinStore();
    store.storePin(vectors.did, "alice", "", "");
    expect(store.checkPin("alice", "did:key:zOTHER", "persistent")).toBe("mismatch");
  });

  test("updates last_seen on re-store", () => {
    const store = new PinStore();
    store.storePin(vectors.did, "alice", "", "server1");
    const first = store.pins.get(vectors.did)!;
    const firstSeen = first.first_seen;

    store.storePin(vectors.did, "alice", "", "server2");
    const updated = store.pins.get(vectors.did)!;
    expect(updated.first_seen).toBe(firstSeen);
    expect(updated.server).toBe("server2");
  });

  test("serializes and deserializes to YAML", () => {
    const store = new PinStore();
    store.storePin(vectors.did, "alice", "@alice", "https://app.aweb.ai");
    const yaml = store.toYAML();

    const loaded = PinStore.fromYAML(yaml);
    expect(loaded.checkPin("alice", vectors.did, "persistent")).toBe("ok");
    expect(loaded.pins.get(vectors.did)!.handle).toBe("@alice");
  });
});

// --- Keys ---

describe("loadSigningKey", () => {
  test("loads PEM private key", async () => {
    // Create a temp PEM file with our test seed
    const { writeFileSync, mkdtempSync, unlinkSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");

    const dir = mkdtempSync(join(tmpdir(), "aweb-test-"));
    const pemPath = join(dir, "test.key");

    // PEM encode the seed (same format as Go's writePrivateKey)
    const b64Seed = Buffer.from(seed).toString("base64");
    const lines: string[] = [];
    for (let i = 0; i < b64Seed.length; i += 64) {
      lines.push(b64Seed.slice(i, i + 64));
    }
    const pem = `-----BEGIN ED25519 PRIVATE KEY-----\n${lines.join("\n")}\n-----END ED25519 PRIVATE KEY-----\n`;
    writeFileSync(pemPath, pem, { mode: 0o600 });

    try {
      const loaded = await loadSigningKey(pemPath);
      expect(loaded.length).toBe(32);
      expect(Buffer.from(loaded).toString("base64")).toBe(
        Buffer.from(seed).toString("base64"),
      );
    } finally {
      unlinkSync(pemPath);
    }
  });
});
