"use strict";

(() => {
  const csrfKey = "aweb.secrets.console.csrf";
  const notice = document.querySelector("#notice");

  // A session cookie is shared across tabs; its CSRF token is tab-local.
  // Keep authenticated actions hidden until this tab can actually use them.
  const actions = document.querySelector("[data-console-scope]");
  if (actions) {
    try {
      if (sessionStorage.getItem(csrfKey)) {
        actions.hidden = false;
        document.querySelector("#console-reauth-notice").hidden = true;
      }
    } catch {
      // Storage may be disabled. Leave the scoped passkey sign-in visible.
    }
  }

  function decode(value) {
    const text = value.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(text + "=".repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));
  }

  function encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Both login and confirmation send the server's purpose-bound options
  // through the same WebAuthn conversion. B3 verifies UV and purpose.
  async function assertion(options) {
    const publicKey = {...options, challenge: decode(options.challenge)};
    if (options.allowCredentials) publicKey.allowCredentials = options.allowCredentials.map(
      credential => ({...credential, id: decode(credential.id)}),
    );
    const credential = await navigator.credentials.get({publicKey});
    if (!credential) throw new Error("Passkey unavailable");
    return {
      id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
  }

  class SessionRequired extends Error {}

  function requireSignIn() {
    try { sessionStorage.removeItem(csrfKey); } catch {}
    if (actions) actions.hidden = true;
    const prompt = document.querySelector("#console-reauth-notice");
    if (prompt) prompt.hidden = false;
  }

  async function post(path, body) {
    const csrf = sessionStorage.getItem(csrfKey);
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin", cache: "no-store", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      let detail;
      if (response.status === 403) {
        try { detail = (await response.json()).detail; } catch {}
      }
      if (response.status === 401 || (response.status === 403 && detail === "csrf_token_required")) {
        requireSignIn();
        throw new SessionRequired("Sign in again");
      }
      throw new Error("Request refused");
    }
    return response.json();
  }

  // Custody forms use this same helper so stale cookies/tokens recover in
  // exactly the same way as the shell's logout, without duplicated fetch code.
  window.awebSecretsConsole = Object.freeze({post, assertion});

  const login = document.querySelector("#login");
  if (login) login.addEventListener("submit", async event => {
    event.preventDefault();
    const button = login.querySelector("button");
    button.disabled = true;
    notice.textContent = "Waiting for your passkey…";
    try {
      const scope = login.dataset.scope;
      const options = await post("/login/options", {scope});
      const result = await post("/login", {scope, assertion: await assertion(options)});
      if (typeof result.csrf_token !== "string" || !result.csrf_token) throw new Error("Sign-in incomplete");
      sessionStorage.setItem(csrfKey, result.csrf_token);
      window.location.replace("/");
    } catch {
      notice.textContent = "Sign-in could not be completed. Try your passkey again.";
    } finally {
      button.disabled = false;
    }
  });

  const logout = document.querySelector("#logout");
  if (logout) logout.addEventListener("submit", async event => {
    event.preventDefault();
    const button = logout.querySelector("button");
    button.disabled = true;
    try {
      // The existing S4 logout is deliberately bodiless and requires CSRF.
      await post("/logout");
      sessionStorage.removeItem(csrfKey);
      window.location.replace("/login");
    } catch (error) {
      if (!(error instanceof SessionRequired)) {
        notice.textContent = "Sign-out could not be completed. Try again.";
      }
      button.disabled = false;
    }
  });
})();
