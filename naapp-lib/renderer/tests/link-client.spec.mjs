import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { fileURLToPath } from "node:url";

const vectors = JSON.parse(
  await readFile(
    new URL("../../../docs/vectors/link-request-v1.json", import.meta.url),
  ),
);
const seed = Buffer.from(vectors.keys.session.seed_hex, "hex");
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  seed,
]);
const publicKey = createPublicKey(
  createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }),
)
  .export({ format: "der", type: "spki" })
  .subarray(-32);
let server, origin;
test.beforeAll(async () => {
  server = spawn(
    fileURLToPath(new URL("../../.venv/bin/python", import.meta.url)),
    [fileURLToPath(new URL("./link-client-server.py", import.meta.url))],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  origin = await new Promise((resolve, reject) => {
    let output = "";
    server.stdout.on("data", (bytes) => {
      output += bytes;
      if (output.includes("\n"))
        resolve(JSON.parse(output.split("\n")[0]).origin);
    });
    server.once("error", reject);
    server.once("exit", (code) => reject(Error(`Probe server exited ${code}`)));
    server.stderr.on("data", (bytes) => process.stderr.write(bytes));
  });
});
test.afterAll(async () => {
  server?.kill();
});

async function mount(page) {
  await page.goto(origin + "/#k=" + vectors.secrets[0].secret);
  await page.evaluate(async () => {
    const { createLinkClient } = await import("/page-link-client.js");
    window.client = createLinkClient({
      linkId: "lnk-test",
      sessionPath: "/mounted/v1/links/lnk-test/session",
    });
  });
}

test("C4 root signing vectors byte-match in WebCrypto in the browser", async ({
  page,
}) => {
  await page.goto(origin);
  const result = await page.evaluate(
    async ({ vectors, pkcs8, publicKey }) => {
      const { signLinkRequest, sessionDidKey } =
        await import("/page-link-client.js");
      const key = await crypto.subtle.importKey(
        "pkcs8",
        new Uint8Array(pkcs8),
        "Ed25519",
        false,
        ["sign"],
      );
      const pub = await crypto.subtle.importKey(
        "raw",
        new Uint8Array(publicKey),
        "Ed25519",
        true,
        ["verify"],
      );
      const signatures = [];
      for (const vector of vectors.valid) {
        const signed = await signLinkRequest(vector.payload, key);
        signatures.push({
          headers: signed,
          signingBytes:
            "aweb.link-request/1\n" +
            atob(
              signed["X-AWEB-Signed-Payload"]
                .replaceAll("-", "+")
                .replaceAll("_", "/"),
            ),
        });
      }
      return { did: await sessionDidKey(pub), signatures };
    },
    { vectors, pkcs8: [...pkcs8], publicKey: [...publicKey] },
  );
  expect(result.did).toBe(vectors.keys.session.did_key);
  vectors.valid.forEach((vector, i) => {
    expect(result.signatures[i].headers.Authorization).toBe(
      vector.authorization,
    );
    expect(result.signatures[i].headers["X-AWEB-Signed-Payload"]).toBe(
      vector.signed_payload_header,
    );
    expect(result.signatures[i].signingBytes).toBe(vector.signing_bytes);
  });
});

test("exchange strips fragment synchronously and keeps non-extractable keys/secrets private", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.generated = [];
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    crypto.subtle.generateKey = async (...args) => {
      const key = await generate(...args);
      let refused = false;
      try {
        await crypto.subtle.exportKey("pkcs8", key.privateKey);
      } catch {
        refused = true;
      }
      window.generated.push({
        extractable: key.privateKey.extractable,
        refused,
      });
      return key;
    };
    const original = window.fetch;
    window.fetch = (...args) => {
      window.fragmentAtFetch = location.hash;
      return original(...args);
    };
  });
  await mount(page);
  expect(new URL(page.url()).hash).toBe("");
  const metadata = await page.evaluate(() => client.connect());
  expect(metadata.link.page_id).toBe("records");
  expect(JSON.stringify(metadata)).not.toMatch(
    /csrf|secret|session_id|did:key/,
  );
  expect(await page.evaluate(() => window.generated)).toEqual([
    { extractable: false, refused: true },
  ]);
  expect(await page.evaluate(() => window.fragmentAtFetch)).toBe("");
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  expect(await page.evaluate(() => Object.keys(client).sort())).toEqual([
    "clear",
    "connect",
    "csrfToken",
    "request",
  ]);
});

test("real HTTP reads, queries and writes verify exact mounted paths/body and fresh nonces", async ({
  page,
  context,
}) => {
  await context.addCookies([
    { name: "member", value: "not-link-authority", url: origin },
  ]);
  await mount(page);
  const result = await page.evaluate(async () => {
    await client.connect();
    const path =
      "/mounted/v1/pages/records/widgets/table?projection=1&cursor=a%2Fb&sort=name%20asc";
    const read = await client.request(path).then((r) => r.json());
    const body = JSON.stringify({ note: "Bücher ", idempotency_key: "one" });
    const first = await client
      .request("/mounted/v1/pages/records/actions", { method: "POST", body })
      .then((r) => r.json());
    const retry = await client
      .request("/mounted/v1/pages/records/actions", { method: "POST", body })
      .then((r) => r.json());
    return {
      read,
      first,
      retry,
      expected: [...new TextEncoder().encode(body)],
      csrf: typeof client.csrfToken(),
    };
  });
  expect(result.read.verified).toBe(true);
  expect(result.read.path).toBe(
    "/mounted/v1/pages/records/widgets/table?projection=1&cursor=a%2Fb&sort=name%20asc",
  );
  expect(result.first.verified).toBe(true);
  expect(result.first.body).toEqual(result.expected);
  expect(result.retry.body).toEqual(result.first.body);
  expect(
    new Set([result.read.nonce, result.first.nonce, result.retry.nonce]).size,
  ).toBe(3);
  expect(result.first.referrer).toBeNull();
  expect(result.csrf).toBe("string");
});

test("unsafe or normalized targets refuse before sending a credential", async ({
  page,
}) => {
  await mount(page);
  await page.evaluate(() => client.connect());
  const result = await page.evaluate(async () => {
    let calls = 0;
    const original = window.fetch;
    window.fetch = (...args) => {
      ++calls;
      return original(...args);
    };
    const codes = [];
    for (const path of [
      "https://other.invalid/",
      "//other.invalid/x",
      "/a/../b",
      "/%2e%2e/x",
      "/x#secret",
      "/x y",
      "/x?",
      "/x\\y",
    ]) {
      try {
        await client.request(path);
        codes.push("sent");
      } catch (error) {
        codes.push(error.code);
      }
    }
    return { calls, codes };
  });
  expect(result.calls).toBe(0);
  expect(result.codes).toEqual(Array(8).fill("request_invalid"));
});

test("clear during signing prevents dispatch and cannot expose old CSRF after a new page", async ({
  page,
}) => {
  await mount(page);
  await page.evaluate(() => client.connect());
  const result = await page.evaluate(async () => {
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    let release, started;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const held = new Promise((resolve) => {
      started = resolve;
    });
    crypto.subtle.sign = async (...args) => {
      started();
      await gate;
      return sign(...args);
    };
    let sends = 0;
    const fetch = window.fetch;
    window.fetch = (...args) => {
      ++sends;
      return fetch(...args);
    };
    const request = client
      .request("/mounted/v1/pages/records")
      .catch((error) => error.code);
    await held;
    client.clear();
    release();
    const code = await request;
    return { code, sends, csrf: client.csrfToken() };
  });
  expect(result).toEqual({ code: "client_cleared", sends: 0, csrf: null });
});

test("unsupported WebCrypto refuses without an exchange and without retaining the fragment", async ({
  page,
}) => {
  await page.addInitScript(() => {
    crypto.subtle.generateKey = async () => {
      throw new DOMException("unsupported", "NotSupportedError");
    };
  });
  let exchanges = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/session")) ++exchanges;
  });
  await mount(page);
  const code = await page.evaluate(() =>
    client.connect().catch((error) => error.code),
  );
  expect(code).toBe("unsupported_crypto");
  expect(exchanges).toBe(0);
  expect(new URL(page.url()).hash).toBe("");
});

test("the signer refuses malformed C4 payload fields before producing headers", async ({
  page,
}) => {
  await page.goto(origin);
  const cases = vectors.verification_cases.filter((vector) =>
    [
      "unknown-field",
      "missing-nonce",
      "wrong-type",
      "version-true",
      "nonce-short",
      "nonce-uppercase",
      "method-lowercase",
      "issued-at-fractional",
      "body-digest-prefixed",
    ].includes(vector.name),
  );
  const refused = await page.evaluate(
    async ({ cases, pkcs8, valid }) => {
      const { signLinkRequest } = await import("/page-link-client.js");
      const key = await crypto.subtle.importKey(
        "pkcs8",
        new Uint8Array(pkcs8),
        "Ed25519",
        false,
        ["sign"],
      );
      const result = [];
      for (const { payload } of [
        ...cases,
        { payload: { ...valid, link_id: 1 } },
      ]) {
        try {
          await signLinkRequest(payload, key);
          result.push("signed");
        } catch (error) {
          result.push(error.code);
        }
      }
      return result;
    },
    { cases, pkcs8: [...pkcs8], valid: vectors.valid[0].payload },
  );
  expect(refused).toEqual(Array(cases.length + 1).fill("request_invalid"));
});

test("expired sessions require explicit renewal and reload requires reopening the link", async ({
  page,
}) => {
  await mount(page);
  const result = await page.evaluate(async () => {
    const first = await client.connect();
    const before = await client
      .request("/mounted/v1/pages/records")
      .then((r) => r.json());
    const now = Date.now;
    Date.now = () => Date.parse(first.expires_at) + 1;
    const code = await client
      .request("/mounted/v1/pages/records")
      .catch((e) => e.code);
    const csrf = client.csrfToken();
    Date.now = now;
    await client.connect();
    const after = await client
      .request("/mounted/v1/pages/records")
      .then((r) => r.json());
    return { code, csrf, before, after };
  });
  expect(result.code).toBe("session_expired");
  expect(result.csrf).toBeNull();
  expect(result.after.verified).toBe(true);
  expect(result.after.session_id).not.toBe(result.before.session_id);
  await page.reload();
  const missing = await page.evaluate(async () => {
    const { createLinkClient } = await import("/page-link-client.js");
    try {
      createLinkClient({ linkId: "lnk-test" });
      return "accepted";
    } catch (error) {
      return error.code;
    }
  });
  expect(missing).toBe("link_unavailable");
});

test("clear during key generation prevents exchanging the old secret", async ({
  page,
}) => {
  await mount(page);
  const result = await page.evaluate(async () => {
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    let release, started;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const held = new Promise((resolve) => {
      started = resolve;
    });
    crypto.subtle.generateKey = async (...args) => {
      started();
      await gate;
      return generate(...args);
    };
    let sends = 0;
    const fetch = window.fetch;
    window.fetch = (...args) => {
      ++sends;
      return fetch(...args);
    };
    const pending = client.connect().catch((error) => error.code);
    await held;
    client.clear();
    release();
    return { code: await pending, sends, csrf: client.csrfToken() };
  });
  expect(result).toEqual({ code: "client_cleared", sends: 0, csrf: null });
});

test("binary bodies are snapshotted and redirect responses cannot forward credentials", async ({
  page,
}) => {
  await mount(page);
  await page.evaluate(() => client.connect());
  const paths = [];
  page.on("request", (request) => paths.push(new URL(request.url()).pathname));
  const result = await page.evaluate(async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const pending = client.request("/mounted/v1/pages/records/actions", {
      method: "POST",
      body: bytes,
      contentType: "application/octet-stream",
    });
    bytes.fill(255);
    const response = await pending.then((r) => r.json());
    let redirected = false;
    try {
      await client.request("/mounted/redirect");
      redirected = true;
    } catch {}
    return { response, redirected };
  });
  expect(result.response.verified).toBe(true);
  expect(result.response.body).toEqual([1, 2, 3]);
  expect(result.redirected).toBe(false);
  expect(paths).not.toContain("/mounted/must-not-follow");
});

test("a cleared exchange response cannot install its session", async ({
  page,
}) => {
  await mount(page);
  const result = await page.evaluate(async () => {
    const fetch = window.fetch;
    let release, started;
    const held = new Promise((resolve) => {
      started = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    window.fetch = async (...args) => {
      const response = await fetch(...args);
      const json = response.json.bind(response);
      response.json = async () => {
        const body = await json();
        started();
        await gate;
        return body;
      };
      return response;
    };
    const pending = client.connect().catch((error) => error.code);
    await held;
    client.clear();
    release();
    return {
      code: await pending,
      csrf: client.csrfToken(),
      next: await client.connect().catch((error) => error.code),
    };
  });
  expect(result).toEqual({
    code: "client_cleared",
    csrf: null,
    next: "client_cleared",
  });
});

test("malformed fragment is scrubbed before the constructor refuses", async ({
  page,
}) => {
  await page.goto(origin + "/#k=not-a-secret");
  const code = await page.evaluate(async () => {
    const { createLinkClient } = await import("/page-link-client.js");
    try {
      createLinkClient({ linkId: "lnk-test" });
      return "accepted";
    } catch (error) {
      return error.code;
    }
  });
  expect(code).toBe("link_unavailable");
  expect(new URL(page.url()).hash).toBe("");
});

for (const [status, code] of [
  [404, "link_unavailable"],
  [429, "safety_rate_limited"],
  [503, "authority_unavailable"],
  [403, "current_member_required"],
  ["malformed", "exchange_refused"],
  ["not-json", "exchange_refused"],
]) {
  test(`N5 exchange refusal ${status} preserves code/status without a session or retry`, async ({
    page,
  }) => {
    let exchanges = 0;
    page.on("request", (request) => {
      if (request.url().includes("/session")) ++exchanges;
    });
    await page.goto(origin + "/#k=" + vectors.secrets[0].secret);
    const result = await page.evaluate(async (refusal) => {
      const { createLinkClient } = await import("/page-link-client.js");
      const client = createLinkClient({
        linkId: "lnk-test",
        sessionPath: `/mounted/v1/links/lnk-test/session?refusal=${refusal}`,
      });
      const error = await client.connect().then(
        () => ({ code: "accepted" }),
        (error) => ({ code: error.code, status: error.status }),
      );
      const request = await client.request("/mounted/v1/pages/records").then(
        () => "sent",
        (error) => error.code,
      );
      return { error, request, csrf: client.csrfToken() };
    }, status);
    expect(result.error).toEqual({
      code,
      status: typeof status === "number" ? status : 503,
    });
    expect(result.csrf).toBeNull();
    expect(result.request).toBe("session_expired");
    expect(exchanges).toBe(1);
  });
}

// Hold the real fetch after the HTTP response has arrived, to place the
// session boundary between server admission and the client continuation.
async function holdPost(page) {
  await page.evaluate(() => {
    const original = window.fetch;
    let release, started;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    window.postHeld = new Promise((resolve) => {
      started = resolve;
    });
    window.releasePost = release;
    window.postSignal = null;
    window.clientTraffic = [];
    window.fetch = async (...args) => {
      window.clientTraffic.push({
        path: new URL(args[0]).pathname,
        method: args[1]?.method || "GET",
      });
      const response = await original(...args);
      if (
        args[1]?.method === "POST" &&
        new URL(args[0]).pathname.endsWith("/actions")
      ) {
        window.postSignal = args[1].signal;
        started();
        await gate;
        if (window.postSignal.aborted)
          throw new DOMException("Aborted", "AbortError");
      }
      return response;
    };
    window.postResult = client
      .request("/mounted/v1/pages/records/actions", {
        method: "POST",
        body: '{"idempotency_key":"held-write"}',
      })
      .then(
        async (response) => ({
          status: response.status,
          body: await response.json(),
        }),
        (error) => ({ code: error.code }),
      );
  });
  await page.evaluate(() => window.postHeld);
}

test("a committed POST response survives session expiry during fetch", async ({
  page,
}) => {
  await mount(page);
  const metadata = await page.evaluate(() => client.connect());
  await holdPost(page);
  await page.evaluate((expires) => {
    Date.now = () => Date.parse(expires) + 1;
    window.releasePost();
  }, metadata.expires_at);
  const result = await page.evaluate(() => window.postResult);
  expect(result.status).toBe(200);
  expect(result.body.verified).toBe(true);
  expect(await page.evaluate(() => window.clientTraffic)).toHaveLength(1);
});

test("renewal waits for a POST response and never aborts or resends it", async ({
  page,
}) => {
  await mount(page);
  await page.evaluate(() => client.connect());
  await holdPost(page);
  const waiting = await page.evaluate(async () => {
    window.renewalResult = client.connect().then(
      () => "renewed",
      (error) => error.code,
    );
    return {
      aborted: window.postSignal.aborted,
      exchanges: window.clientTraffic.filter((r) => r.path.endsWith("/session"))
        .length,
    };
  });
  expect(waiting).toEqual({ aborted: false, exchanges: 0 });
  await page.evaluate(() => window.releasePost());
  const result = await page.evaluate(async () => ({
    post: await window.postResult,
    renewal: await window.renewalResult,
    writes: window.clientTraffic.filter((r) => r.path.endsWith("/actions"))
      .length,
  }));
  expect(result.post.status).toBe(200);
  expect(result.post.body.verified).toBe(true);
  expect(result.renewal).toBe("renewed");
  expect(result.writes).toBe(1);
  expect(await page.evaluate(() => window.postSignal.aborted)).toBe(false);
});

test("clear remains terminal and aborts a POST waiting for its response", async ({
  page,
}) => {
  await mount(page);
  await page.evaluate(() => client.connect());
  await holdPost(page);
  await page.evaluate(() => client.clear());
  expect(await page.evaluate(() => window.postSignal.aborted)).toBe(true);
  await page.evaluate(() => window.releasePost());
  expect(await page.evaluate(() => window.postResult)).toEqual({
    code: "client_cleared",
  });
  expect(await page.evaluate(() => client.csrfToken())).toBeNull();
  expect(await page.evaluate(() => window.clientTraffic)).toHaveLength(1);
});
