import { createHash } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { afterEach, expect, test } from "vitest";
import { createShadowedPrincipalFixture } from "../../channel-core/test/helpers/config_fixture.js";
import { launchPackagedMCPChild } from "./helpers/packaged_mcp.js";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

interface ProbeRequest {
  authorization: string;
  timestamp: string;
  url: string;
}

interface ProbeServer {
  close(): Promise<void>;
  nextRequest(): Promise<ProbeRequest>;
  requests: ProbeRequest[];
  url: string;
}

const channelRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const originalHome = process.env.HOME;
const originalIdentityHome = process.env.AWEB_IDENTITY_HOME;

let child: ChildProcessWithoutNullStreams | undefined;
let externalServer: ProbeServer | undefined;
let shadowServer: ProbeServer | undefined;

afterEach(async () => {
  child?.kill("SIGTERM");
  child = undefined;
  await externalServer?.close();
  await shadowServer?.close();
  externalServer = undefined;
  shadowServer = undefined;
  restoreEnvironment("HOME", originalHome);
  restoreEnvironment("AWEB_IDENTITY_HOME", originalIdentityHome);
});

test("packaged Claude MCP child inherits AWEB_IDENTITY_HOME and signs as the external principal", async () => {
  const { external, shadow, workdir } = await createShadowedPrincipalFixture();
  externalServer = await startProbeServer();
  shadowServer = await startProbeServer();
  setAwebURL(external.identityHome, externalServer.url);
  setAwebURL(shadow.identityHome, shadowServer.url);

  process.env.HOME = mkdtempSync(join(tmpdir(), "claude-channel-home-"));
  process.env.AWEB_IDENTITY_HOME = external.identityHome;

  const launched = await launchPackagedMCPChild(channelRoot, workdir);
  child = launched.child;
  expect(launched.args).toEqual([join(channelRoot, "dist", "index.js")]);

  const observed = await withTimeout(
    Promise.race([
      externalServer.nextRequest().then((request) => ({ source: "external", request } as const)),
      shadowServer.nextRequest().then((request) => ({ source: "shadow", request } as const)),
    ]),
    5_000,
    () => `packaged MCP child did not reach either fixture server\n${launched.stderr()}`,
  );

  expect(observed.source).toBe("external");
  const request = observed.request;
  expect(request.url).toMatch(/^\/v1\/events\/stream\?deadline=/);
  expect(shadowServer.requests).toHaveLength(0);

  const [scheme, did, encodedSignature] = request.authorization.split(" ");
  expect(scheme).toBe("DIDKey");
  expect(did).toBe(external.did);
  expect(did).not.toBe(shadow.did);

  const bodyHash = createHash("sha256").update("", "utf8").digest("hex");
  const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"team_id":${JSON.stringify(external.teamID)},"timestamp":${JSON.stringify(request.timestamp)}}`;
  const signature = Buffer.from(encodedSignature, "base64url");
  const message = new TextEncoder().encode(payload);
  expect(ed.verify(signature, message, ed.getPublicKey(external.seed))).toBe(true);
  expect(ed.verify(signature, message, ed.getPublicKey(shadow.seed))).toBe(false);
});

async function startProbeServer(): Promise<ProbeServer> {
  const requests: ProbeRequest[] = [];
  let receive: ((request: ProbeRequest) => void) | undefined;
  const next = new Promise<ProbeRequest>((resolve) => { receive = resolve; });
  const server = createServer((request: IncomingMessage, response) => {
    const observed = {
      authorization: request.headers.authorization || "",
      timestamp: String(request.headers["x-aweb-timestamp"] || ""),
      url: request.url || "",
    };
    requests.push(observed);
    receive?.(observed);
    receive = undefined;
    response.writeHead(200, {
      "cache-control": "no-cache",
      connection: "keep-alive",
      "content-type": "text/event-stream",
    });
    response.write(": connected\n\n");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("probe server did not bind a TCP port");

  return {
    requests,
    url: `http://127.0.0.1:${address.port}`,
    nextRequest: () => next,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

function setAwebURL(identityHome: string, url: string): void {
  const path = join(identityHome, "workspace.yaml");
  const workspace = readFileSync(path, "utf8");
  writeFileSync(path, workspace.replace(/^aweb_url: .*$/m, `aweb_url: ${url}`));
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: () => string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message())), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
