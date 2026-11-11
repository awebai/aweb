"use strict";

(() => {
  const {handoffId, purpose} = document.body.dataset;
  const prefix = `/handoff/${handoffId}/${purpose}`;
  const action = document.getElementById("handoff-action");
  const confirm = document.getElementById("handoff-confirm");
  const allow = document.getElementById("handoff-allow");
  const status = document.getElementById("handoff-status");
  let csrf;

  document.getElementById("handoff-origin").textContent = window.location.origin;

  async function request(suffix, body) {
    const headers = body === undefined ? {} : {
      "Content-Type": "application/json", "X-CSRF-Token": csrf,
    };
    const response = await fetch(prefix + suffix, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin", cache: "no-store", redirect: "error", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error("handoff_refused");
    return response.json();
  }

  function failed() {
    // Completion may have committed even if its response was lost. Never
    // replay a completion or an Allow, and never collect the result here.
    action.disabled = true;
    confirm.disabled = true;
    allow.hidden = true;
    csrf = undefined;
    document.body.dataset.handoffState = "refused";
    status.textContent = "This request could not be completed. Return to your terminal and start again.";
  }

  function complete(result) {
    if (typeof result.redirect_uri !== "string") throw new Error("handoff_refused");
    csrf = undefined;
    document.body.dataset.handoffState = "complete";
    status.textContent = "Complete. Returning to your terminal…";
    // Only the existing completion route supplies the stored, validated
    // loopback URI. No URL, scope, code or verifier comes from page parameters.
    window.location.assign(result.redirect_uri);
  }

  async function load() {
    try {
      const state = await request("");
      if (typeof state.csrf_token !== "string" || !state.csrf_token) throw new Error("handoff_refused");
      for (const [field, id] of [
        ["principal", "handoff-principal"], ["role", "handoff-role"],
        ["installation_id", "handoff-installation"],
      ]) {
        if (typeof state.scope?.[field] !== "string") throw new Error("handoff_refused");
        document.getElementById(id).textContent = state.scope[field];
      }
      csrf = state.csrf_token;
      document.getElementById("handoff-scope").hidden = false;
      status.textContent = "Check the identity and role before continuing.";
      action.disabled = false;
      document.body.dataset.handoffState = "ready";
    } catch {
      failed();
    }
  }

  action.addEventListener("click", async () => {
    action.disabled = true;
    document.body.dataset.handoffState = "verifying";
    status.textContent = "Follow your browser’s passkey prompt.";
    try {
      const options = await request("/options", {});
      if (purpose === "credential") {
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        complete(await request("/complete", {credential: credential.toJSON()}));
      } else {
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        const result = await request("/login", {assertion: credential.toJSON()});
        if (result.logged_in !== true) throw new Error("handoff_refused");
        action.hidden = true;
        status.textContent = "Passkey verified. Review the identity and role, then choose Allow.";
        allow.hidden = false;
        document.body.dataset.handoffState = "awaiting-allow";
        document.getElementById("handoff-allow-title").focus();
      }
    } catch (error) {
      if (error.name === "NotAllowedError") {
        // No completion was sent: an explicit retry obtains fresh options.
        status.textContent = "The passkey prompt was cancelled. You can try again.";
        action.disabled = false;
        document.body.dataset.handoffState = "ready";
      } else {
        failed();
      }
    }
  });

  confirm.addEventListener("click", async () => {
    confirm.disabled = true;
    document.body.dataset.handoffState = "allowing";
    status.textContent = "Allowing this terminal session…";
    try {
      complete(await request("/allow", {allow: true}));
    } catch {
      failed();
    }
  });

  load();
})();
