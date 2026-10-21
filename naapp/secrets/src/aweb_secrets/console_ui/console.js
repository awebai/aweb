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

  async function post(path, body, csrf) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin", cache: "no-store", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error("Request refused");
    return response.json();
  }

  const login = document.querySelector("#login");
  if (login) login.addEventListener("submit", async event => {
    event.preventDefault();
    const button = login.querySelector("button");
    button.disabled = true;
    notice.textContent = "Waiting for your passkey…";
    try {
      const scope = login.dataset.scope;
      const options = await post("/login/options", {scope});
      const publicKey = {...options, challenge: decode(options.challenge)};
      if (options.allowCredentials) publicKey.allowCredentials = options.allowCredentials.map(
        credential => ({...credential, id: decode(credential.id)}),
      );
      const credential = await navigator.credentials.get({publicKey});
      if (!credential) throw new Error("Passkey unavailable");
      const result = await post("/login", {scope, assertion: {
        id: credential.id, rawId: encode(credential.rawId), type: credential.type,
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          authenticatorData: encode(credential.response.authenticatorData),
          signature: encode(credential.response.signature),
          userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      }});
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
      await post("/logout", undefined, sessionStorage.getItem(csrfKey));
      sessionStorage.removeItem(csrfKey);
      window.location.replace("/login");
    } catch {
      notice.textContent = "Sign-out could not be completed. Try again.";
      button.disabled = false;
    }
  });
})();
