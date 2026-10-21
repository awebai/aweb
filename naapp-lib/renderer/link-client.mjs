// Host transport only. No capability secret, key or session enters page JSON.
import { canonical } from "./digests.mjs";

const utf8 = new TextEncoder();
const id = /^[A-Za-z0-9._-]{1,128}$/;
const methods = /^[A-Z]{3,7}$/;
const matches = (pattern, value) =>
  typeof value === "string" && pattern.test(value);
const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
const hex = (bytes) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const timestamp = (date) => date.toISOString().replace(/\.\d{3}Z$/, "Z");
const fail = (code, status = 0) =>
  Object.assign(new Error(code), { code, status });

export async function sessionDidKey(publicKey) {
  if (publicKey.type !== "public" || publicKey.algorithm.name !== "Ed25519")
    throw fail("request_invalid");
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  const multicodec = new Uint8Array([0xed, 0x01, ...raw]);
  let integer = BigInt("0x" + hex(multicodec)),
    encoded = "";
  while (integer) {
    encoded = base58[Number(integer % 58n)] + encoded;
    integer /= 58n;
  }
  return "did:key:z" + encoded;
}

export async function signLinkRequest(payload, privateKey) {
  const fields = [
    "v",
    "type",
    "link_id",
    "session_id",
    "method",
    "path",
    "body_sha256",
    "nonce",
    "issued_at",
  ];
  if (
    !payload ||
    Object.keys(payload).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(payload, field)) ||
    payload.v !== 1 ||
    payload.type !== "aweb.link-request" ||
    !matches(id, payload.link_id) ||
    !matches(id, payload.session_id) ||
    !matches(methods, payload.method) ||
    !matches(/^\/[\x21-\x7e]{0,2047}$/, payload.path) ||
    !matches(/^[0-9a-f]{64}$/, payload.body_sha256) ||
    !matches(/^[0-9a-f]{32}$/, payload.nonce) ||
    !matches(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, payload.issued_at) ||
    !Number.isFinite(Date.parse(payload.issued_at)) ||
    timestamp(new Date(payload.issued_at)) !== payload.issued_at
  )
    throw fail("request_invalid");
  const encoded = canonical(payload);
  const sessionId = payload.session_id;
  const bytes = utf8.encode(encoded);
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    utf8.encode("aweb.link-request/1\n" + encoded),
  );
  return {
    Authorization: `AWEB-Link-Request ${sessionId} ${b64url(new Uint8Array(signature))}`,
    "X-AWEB-Signed-Payload": b64url(bytes),
  };
}

function token(value, size) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value))
    return false;
  try {
    const bytes = Uint8Array.from(
      atob(value.replaceAll("-", "+").replaceAll("_", "/")),
      (c) => c.charCodeAt(0),
    );
    return bytes.length === size && b64url(bytes) === value;
  } catch {
    return false;
  }
}

/** Call synchronously from the host's first script, before any other fetch.
 * Paths are exact same-origin external request targets, including mount/query.
 * clear() is terminal; an authority change requires a new client. */
export function createLinkClient({
  linkId,
  sessionPath = `/v1/links/${linkId}/session`,
} = {}) {
  let secret = /^#k=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1];
  // Scrub even a malformed fragment, before validation, key generation or I/O.
  history.replaceState(history.state, "", location.pathname + location.search);
  const origin = location.origin;
  let epoch = 0,
    session = null,
    connecting = null,
    cleared = false;
  let controller = new AbortController();
  if (!matches(id, linkId) || !token(secret, 32))
    throw fail("link_unavailable");

  function target(path) {
    if (typeof path !== "string" || !/^\/[\x21-\x7e]{0,2047}$/.test(path))
      throw fail("request_invalid");
    const parsed = new URL(path, origin);
    if (
      parsed.origin !== origin ||
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      parsed.pathname + parsed.search !== path
    )
      throw fail("request_invalid");
    return parsed.href;
  }
  const exchangeURL = target(sessionPath);
  const current = (expected) => {
    if (cleared) throw fail("client_cleared");
    if (expected !== epoch) throw fail("session_changed");
  };
  const active = (expected) => {
    current(expected);
    if (!session || Date.now() >= session.expiry) throw fail("session_expired");
  };
  const options = (signal) => ({
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal,
  });

  function connect() {
    if (cleared) return Promise.reject(fail("client_cleared"));
    if (connecting) return connecting;
    const expected = ++epoch;
    controller.abort();
    controller = new AbortController();
    const signal = controller.signal;
    session = null;
    const pending = (async () => {
      let pair;
      try {
        pair = await crypto.subtle.generateKey("Ed25519", false, [
          "sign",
          "verify",
        ]);
      } catch {
        current(expected);
        throw fail("unsupported_crypto");
      }
      current(expected);
      const did = await sessionDidKey(pair.publicKey);
      current(expected);
      const response = await fetch(exchangeURL, {
        ...options(signal),
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret, session_did_key: did }),
      });
      current(expected);
      const data = await response.json();
      current(expected);
      if (!data || typeof data !== "object") throw fail("session_invalid");
      if (!response.ok)
        throw fail(
          typeof data.code === "string" ? data.code : "exchange_refused",
          response.status,
        );
      const expiry = Date.parse(data.expires_at);
      if (
        !matches(id, data.session_id) ||
        !token(data.csrf_token, 16) ||
        !Number.isFinite(expiry) ||
        expiry <= Date.now() ||
        !data.link ||
        typeof data.link.page_id !== "string"
      )
        throw fail("session_invalid");
      session = {
        id: data.session_id,
        csrf: data.csrf_token,
        expiry,
        key: pair.privateKey,
      };
      return {
        expires_at: data.expires_at,
        link: {
          page_id: data.link.page_id,
          mode: data.link.mode,
          actions: [...(data.link.actions || [])],
        },
      };
    })().catch((error) => {
      current(expected);
      throw error;
    });
    connecting = pending;
    // Avoid an unobserved rejected promise from a standalone finally().
    pending.then(
      () => {
        if (connecting === pending) connecting = null;
      },
      () => {
        if (connecting === pending) connecting = null;
      },
    );
    return pending;
  }

  async function request(
    path,
    { method = "GET", body, contentType = "application/json" } = {},
  ) {
    const expected = epoch;
    active(expected);
    const url = target(path);
    if (
      !matches(methods, method) ||
      (["GET", "HEAD"].includes(method) && body !== undefined)
    )
      throw fail("request_invalid");
    // Snapshot bytes before hashing: mutation cannot change the dispatched body.
    const bytes =
      body === undefined
        ? new Uint8Array()
        : typeof body === "string"
          ? utf8.encode(body)
          : body instanceof Uint8Array
            ? new Uint8Array(body)
            : null;
    if (!bytes) throw fail("request_invalid");
    const snapshot = session,
      signal = controller.signal;
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    active(expected);
    const headers = await signLinkRequest(
      {
        v: 1,
        type: "aweb.link-request",
        link_id: linkId,
        session_id: snapshot.id,
        method,
        path,
        body_sha256: hex(new Uint8Array(digest)),
        nonce: hex(crypto.getRandomValues(new Uint8Array(16))),
        issued_at: timestamp(new Date()),
      },
      snapshot.key,
    );
    active(expected);
    if (!["GET", "HEAD"].includes(method))
      headers["X-AWEB-CSRF"] = snapshot.csrf;
    if (body !== undefined) headers["Content-Type"] = contentType;
    try {
      const response = await fetch(url, {
        ...options(signal),
        method,
        headers,
        ...(body !== undefined ? { body: bytes } : {}),
      });
      active(expected);
      return response;
    } catch (error) {
      current(expected);
      throw error;
    }
  }
  return {
    connect,
    request,
    csrfToken: () =>
      !cleared && session && Date.now() < session.expiry ? session.csrf : null,
    clear() {
      cleared = true;
      ++epoch;
      controller.abort();
      secret = null;
      session = null;
      connecting = null;
    },
  };
}
