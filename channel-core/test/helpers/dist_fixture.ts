// Fixtures for the behaviour tests that run against a built adapter bundle
// (scripts/typescript-dist). The bundle is the code under test; these helpers
// only write workspaces and registry answers.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { computeDIDKey, computeStableID } from "../../src/identity/did.js";
import { canonicalDidLogPayload, type DidKeyResolution } from "../../src/identity/registry.js";

export { writeSigningKey, writeTeamCertificate, writeTeamState, writeTestPrincipal, writeWorkspaceBinding } from "./config_fixture.js";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

export function temporaryDirectory(prefix: string): string {
  return realpathSync(mkdtempSync(join(tmpdir(), prefix)));
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * The registry's key answer for a genesis entry signed by `signer`, claiming
 * `stableID`. With stableID derived from signer it is a valid genesis; with any
 * other stableID every hash and signature still verifies, and only the
 * genesis-to-did:aw binding refuses it.
 */
export function genesisKeyAnswer(signer: Uint8Array, stableID: string): DidKeyResolution {
  const didKey = computeDIDKey(ed.getPublicKey(signer));
  const head = {
    authorized_by: didKey,
    new_did_key: didKey,
    operation: "create",
    prev_entry_hash: null,
    previous_did_key: null,
    seq: 1,
    state_hash: hex(sha256(new TextEncoder().encode(
      `{"current_did_key":"${didKey}","did_aw":"${stableID}"}`,
    ))),
    timestamp: "2026-07-26T00:00:00Z",
  };
  const payload = canonicalDidLogPayload(stableID, { ...head, entry_hash: "", signature: "" });
  const signature = Buffer.from(ed.sign(new TextEncoder().encode(payload), signer))
    .toString("base64")
    .replace(/=+$/, "");
  return {
    did_aw: stableID,
    current_did_key: didKey,
    log_head: { ...head, entry_hash: hex(sha256(new TextEncoder().encode(payload))), signature },
  } as DidKeyResolution;
}

export function stableIDOf(seed: Uint8Array): string {
  return computeStableID(ed.getPublicKey(seed));
}

export function didKeyOf(seed: Uint8Array): string {
  return computeDIDKey(ed.getPublicKey(seed));
}

export type Handler = (request: IncomingMessage, response: ServerResponse) => void;

/** An HTTP server on 127.0.0.1 owned by the test; close() also ends its sockets. */
export async function startLoopbackServer(handler: Handler): Promise<{ server: Server; url: string; close(): Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("loopback server did not bind a TCP port");
  return {
    server,
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

export function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}
