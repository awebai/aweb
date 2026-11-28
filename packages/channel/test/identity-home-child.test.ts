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
  body: string;
  method: string;
  signedPayload: string;
  timestamp: string;
  url: string;
}

interface ProbeServer {
  close(): Promise<void>;
  nextRequest(matches?: (request: ProbeRequest) => boolean): Promise<ProbeRequest>;
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

  const launched = await launchPackagedMCPChild(channelRoot, workdir, {
    AWEB_IDENTITY_HOME: process.env.AWEB_IDENTITY_HOME,
  });
  child = launched.child;
  expect(launched.args).toEqual([join(channelRoot, "dist", "index.js")]);

  const observed = await withTimeout(
    Promise.race([
      Promise.all([
        externalServer.nextRequest((request) => request.url === "/v1/agents/heartbeat"),
        externalServer.nextRequest((request) => /^\/v1\/events\/stream\?deadline=/.test(request.url)),
      ]).then((requests) => ({ source: "external", requests } as const)),
      shadowServer.nextRequest().then((request) => ({ source: "shadow", requests: [request] } as const)),
    ]),
    5_000,
    () => `packaged MCP child did not send both heartbeat and stream requests\n${launched.stderr()}`,
  );

  expect(observed.source).toBe("external");
  expect(observed.requests).toHaveLength(2);
  expect(observed.requests.map((request) => request.method)).toEqual(["POST", "GET"]);
  expect(shadowServer.requests).toHaveLength(0);

  for (const request of observed.requests) {
    const [scheme, did, encodedSignature] = request.authorization.split(" ");
    expect(scheme).toBe("DIDKey");
    expect(did).toBe(external.did);
    expect(did).not.toBe(shadow.did);

    const message = Buffer.from(request.signedPayload, "base64url");
    expect(JSON.parse(message.toString("utf8"))).toEqual({
      aud: externalServer.url,
      body_sha256: createHash("sha256").update(request.body, "utf8").digest("hex"),
      method: request.method,
      path: request.url,
      team_id: external.teamID,
      timestamp: request.timestamp,
      v: 2,
    });
    const signature = Buffer.from(encodedSignature, "base64url");
    expect(ed.verify(signature, message, ed.getPublicKey(external.seed))).toBe(true);
    expect(ed.verify(signature, message, ed.getPublicKey(shadow.seed))).toBe(false);
  }
});

async function startProbeServer(): Promise<ProbeServer> {
  const requests: ProbeRequest[] = [];
  const waiting = new Map<(request: ProbeRequest) => void, (request: ProbeRequest) => boolean>();
  const server = createServer(async (request: IncomingMessage, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const observed = {
      authorization: request.headers.authorization || "",
      body: Buffer.concat(chunks).toString("utf8"),
      method: request.method || "",
      signedPayload: String(request.headers["x-aweb-signed-payload"] || ""),
      timestamp: String(request.headers["x-aweb-timestamp"] || ""),
      url: request.url || "",
    };
    requests.push(observed);
    for (const [receive, matches] of waiting) {
      if (matches(observed)) {
        waiting.delete(receive);
        receive(observed);
      }
    }
    if (observed.url === "/v1/agents/heartbeat") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
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
    nextRequest: (matches = () => true) => {
      const observed = requests.find(matches);
      return observed ? Promise.resolve(observed) : new Promise((resolve) => waiting.set(resolve, matches));
    },
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
