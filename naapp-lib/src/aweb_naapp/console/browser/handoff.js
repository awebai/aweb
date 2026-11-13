"use strict";

import { validateProtectedPresentation } from "/handoff-assets/protected-presentation.mjs";
import { operationTable } from "/handoff-assets/operations.mjs";

(() => {
  const {handoffId, purpose} = document.body.dataset;
  const prefix = `/handoff/${handoffId}/${purpose}`;
  const action = document.getElementById("handoff-action");
  const confirm = document.getElementById("handoff-confirm");
  const allow = document.getElementById("handoff-allow");
  const status = document.getElementById("handoff-status");
  const governance = purpose === "governance";
  const loginScope = document.body.dataset.loginScope;
  const csrfKey = document.body.dataset.consoleCsrfKey;
  let loggedIn = false;
  let operationId;
  let submitted = false;
  let frozenRedirect;
  let csrf;

  document.getElementById("handoff-origin").textContent = window.location.origin;

  async function fetchJSON(path, body) {
    const headers = body === undefined ? {} : {
      "Content-Type": "application/json", "X-CSRF-Token": csrf,
    };
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin", cache: "no-store", redirect: "error", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error("handoff_refused");
    return response.json();
  }

  function request(suffix, body) {
    return fetchJSON(prefix + suffix, body);
  }

  function failed() {
    // Completion may have committed even if its response was lost. Never
    // replay a completion or an Allow, and never collect the result here.
    action.disabled = true;
    confirm.disabled = true;
    allow.hidden = true;
    if (governance) {
      document.getElementById("handoff-governance").hidden = true;
      document.getElementById("handoff-scope").hidden = true;
    }
    csrf = undefined;
    document.body.dataset.handoffState = governance && submitted ? "unconfirmed" : "refused";
    status.textContent = governance
      ? "This page cannot confirm the operation’s outcome. Check the existing receipt in your terminal before retrying."
      : "This request could not be completed. Return to your terminal and start again.";
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

  function nonempty(value) {
    return typeof value === "string" && value.length > 0;
  }

  async function governanceState(state) {
    const {payload, digest} = state;
    const {request, subject} = await validateProtectedPresentation(state, handoffId, operationTable);
    operationId = state.operation_id;
    frozenRedirect = request.redirect_uri;
    if (frozenRedirect !== undefined) {
      if (!nonempty(frozenRedirect)) throw new Error("handoff_refused");
      const redirect = new URL(frozenRedirect);
      if (redirect.protocol !== "http:" || redirect.search || redirect.hash ||
          redirect.username || redirect.password) throw new Error("handoff_refused");
    }
    document.getElementById("handoff-act").textContent = request.operation;
    document.getElementById("handoff-target").textContent =
      [subject.principal, subject.role, subject.app_id, subject.installation_id,
        subject.event_class, subject.binding_id, subject.hold_id].filter(value => value !== undefined).join(" · ");
    document.getElementById("handoff-digest").textContent = digest;
    document.getElementById("handoff-fingerprint").textContent = digest.slice(0, 16).match(/.{4}/g).join(" ");
    document.getElementById("handoff-payload").textContent = JSON.stringify(payload, null, 2);
    document.getElementById("handoff-governance").hidden = false;
    action.textContent = "Approve operation with passkey";
    status.textContent = "Compare the act, target and fingerprint with your terminal before approving.";
    document.body.dataset.handoffState = "ready";
    action.disabled = false;
    document.getElementById("handoff-governance-title").focus();
  }

  function governanceComplete(result) {
    if (result.state === "pending") {
      if (result.redirect_uri !== undefined || !nonempty(result.expires_at) ||
          !Number.isFinite(Date.parse(result.expires_at))) throw new Error("handoff_refused");
      action.disabled = true;
      document.body.dataset.handoffState = "pending";
      status.textContent = "The operation is still processing. Check your terminal for its outcome.";
      return;
    }
    if (result.state !== "committed" || !result.result ||
        typeof result.result !== "object" || Array.isArray(result.result) ||
        !nonempty(result.result.signing) || !nonempty(result.result.signature)) {
      throw new Error("handoff_refused");
    }
    if (frozenRedirect === undefined) {
      if (result.redirect_uri !== undefined) throw new Error("handoff_refused");
      csrf = undefined;
      document.body.dataset.handoffState = "complete";
      status.textContent = "Complete. Return to your terminal to read the receipt.";
      return;
    }
    if (!nonempty(result.redirect_uri)) throw new Error("handoff_refused");
    const redirect = new URL(result.redirect_uri);
    const expected = new URL(frozenRedirect);
    expected.searchParams.set("handoff_id", handoffId);
    if (redirect.href !== expected.href) {
      throw new Error("handoff_refused");
    }
    // Only the committed route supplies the frozen loopback; the callback is
    // a code-less hint. aw independently authenticates its receipt read.
    complete(result);
  }

  async function load() {
    try {
      if (governance && !loggedIn) {
        if (!nonempty(loginScope) || !nonempty(csrfKey)) throw new Error("handoff_refused");
        // A new tab shares cookies but not the console token. Always use the
        // existing LOGIN in place; never guess a token or navigate to root.
        status.textContent = "Sign in before reviewing this protected operation.";
        document.body.dataset.handoffState = "login-required";
        action.disabled = false;
        return;
      }
      const state = await request("");
      if (governance) {
        await governanceState(state);
        return;
      }
      if (typeof state.csrf_token !== "string" || !state.csrf_token) throw new Error("handoff_refused");
      for (const [field, id] of [
        ["principal", "handoff-principal"], ["role", "handoff-role"],
        ["installation_id", "handoff-installation"],
      ]) {
        if (typeof state.scope?.[field] !== "string") throw new Error("handoff_refused");
        document.getElementById(id).textContent = state.scope[field];
      }
      // An agent may prepare a session start for its own human parent. Show
      // which agent asked, apart from the identity being signed in.
      if (state.requester !== null && state.requester !== undefined) {
        const { id, address, key_fingerprint: fingerprint } = state.requester;
        if (typeof id !== "string" || !id || typeof fingerprint !== "string" || !fingerprint) {
          throw new Error("handoff_refused");
        }
        if (address !== null && address !== undefined && typeof address !== "string") {
          throw new Error("handoff_refused");
        }
        document.getElementById("handoff-requester").textContent =
          (address ? `${address} (${id})` : id) + ` · key ${fingerprint}`;
        document.getElementById("handoff-requester-label").hidden = false;
        document.getElementById("handoff-requester").hidden = false;
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
      if (governance && !loggedIn) {
        const options = await fetchJSON("/login/options", {scope: loginScope});
        if (options.userVerification !== "required") throw new Error("handoff_refused");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        const result = await fetchJSON("/login", {scope: loginScope, assertion: credential.toJSON()});
        if (!nonempty(result.csrf_token)) throw new Error("handoff_refused");
        // This is S4's own tab token, not a governance cookie or a result.
        sessionStorage.setItem(csrfKey, result.csrf_token);
        csrf = result.csrf_token;
        loggedIn = true;
        await load();
        return;
      }
      const options = await request("/options", {});
      if (governance) {
        if (!operationId || options.userVerification !== "required") throw new Error("handoff_refused");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        submitted = true;
        governanceComplete(await request("/execute", {assertion: credential.toJSON()}));
        return;
      }
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
        document.body.dataset.handoffState = governance && !loggedIn ? "login-required" : "ready";
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
