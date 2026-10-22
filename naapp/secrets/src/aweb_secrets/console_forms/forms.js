"use strict";

(() => {
  const api = window.awebSecretsConsole;
  const status = document.querySelector("#form-status");
  let token = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
  // Strip the personal locator immediately; keep it only in this transient closure.
  if (window.location.hash) history.replaceState(null, "", window.location.pathname + window.location.search);
  const actions = document.querySelector("[data-console-scope]");

  function inlineLogin() {
    const existing = document.querySelector("#approval-login");
    if (existing) return existing;
    const prompt = document.querySelector("#console-reauth-notice");
    const form = document.createElement("form");
    form.id = "approval-login";
    form.method = "post";
    form.action = "/login";
    const button = document.createElement("button");
    button.type = "submit";
    button.disabled = true;
    button.textContent = "Sign in with your passkey";
    const feedback = document.createElement("p");
    feedback.setAttribute("role", "status");
    form.append(button, feedback);
    prompt.append(form);
    document.querySelector("#console-reauth").hidden = true;
    return form;
  }

  function offerSignIn(login) {
    const button = login.querySelector("button");
    const feedback = login.querySelector("p") || status;
    button.disabled = true;
    if (!token) {
      feedback.textContent = "Open the approval link sent to your registered contact.";
      return;
    }
    api.post("/approvals/sign-in", {token}).then(locator => {
      const scope = locator.scope;
      login.addEventListener("submit", async event => {
        event.preventDefault();
        button.disabled = true;
        try {
          const options = await api.post("/login/options", {scope});
          const assertion = await api.assertion(options);
          const signedIn = await api.post("/login", {scope, assertion});
          if (typeof signedIn.csrf_token !== "string" || !signedIn.csrf_token) throw new Error("Sign-in incomplete");
          sessionStorage.setItem("aweb.secrets.console.csrf", signedIn.csrf_token);
          // A hash-only navigation keeps the old document. Fetch it anew with S4.
          history.replaceState(null, "", "/approvals#token=" + encodeURIComponent(token));
          window.location.reload();
        } catch {
          feedback.textContent = "Sign-in could not be completed. Try your passkey again.";
          button.disabled = false;
        }
      });
      button.disabled = false;
    }).catch(() => {
      token = "";
      feedback.textContent = "This approval link is unavailable. Open the link sent to you.";
    });
  }

  const login = document.querySelector("#approval-login");
  if (login || (actions && actions.hidden && token && document.querySelector("#confirm-change"))) {
    offerSignIn(login || inlineLogin());
    return;
  }
  const tokenForm = document.querySelector("#backend-token");
  if (tokenForm) tokenForm.addEventListener("submit", async event => {
    event.preventDefault();
    const input = document.querySelector("#service-account-token");
    const button = tokenForm.querySelector("button");
    let value = input.value;
    input.value = "";
    button.disabled = true;
    status.textContent = "Saving your draft…";
    try {
      const staged = await api.post(tokenForm.action, {value});
      value = "";
      const root = "/installations/" + encodeURIComponent(tokenForm.dataset.installation) + "/change-sets";
      const drafted = await api.post(root, {
        changes: [{kind: "backend_credential", op: "create", ref: "onepassword", after: staged}],
        sealed: [{secret_id: staged.credential_id, version: staged.version}],
        reason: "Connect the team's 1Password service account",
      });
      status.textContent = "Draft saved. Open the approval link sent to your registered contact to confirm it.";
      status.dataset.state = "pending";
      const link = document.createElement("a");
      link.href = root + "/" + encodeURIComponent(drafted.change_id) + "/review";
      link.textContent = "Review this draft";
      status.append(document.createTextNode(" "), link);
    } catch {
      status.textContent = "The draft could not be saved. Check your sign-in and enter the token again.";
    } finally {
      value = "";
      input.value = "";
      button.disabled = false;
    }
  });

  const confirm = document.querySelector("#confirm-change");
  if (!confirm) return;
  let frozen;
  let decided = false;
  let root;

  function fact(name, value) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = name;
    description.textContent = String(value);
    document.querySelector("#change-facts").append(term, description);
  }

  function render(projection) {
    frozen = projection;
    const change = projection.change;
    root = "/installations/" + encodeURIComponent(change.installation_id) + "/change-sets/" + encodeURIComponent(change.change_id);
    fact("Team", change.team_id);
    fact("Expires", new Date(change.expires_at).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "long"}));
    for (const item of change.changes) fact("Service-account token version", item.after.version);
    document.querySelector("#change-reason").textContent = change.reason;
    document.querySelector("#change-summary").hidden = false;
    document.querySelector("#change-summary").dataset.state = projection.state;
    decided = projection.approval_state === "approved" && projection.can_confirm;
    const pending = projection.approval_state === "pending" && Boolean(token);
    confirm.disabled = projection.state !== "pending" || (!decided && !pending);
    confirm.hidden = projection.state !== "pending";
    confirm.textContent = decided ? "Apply the approved change" : "Confirm with your passkey";
    document.querySelector("#approval-instructions").textContent = decided
      ? "Your fresh passkey approval is recorded. Apply this exact change."
      : pending ? "Review the frozen change, then confirm it with your passkey."
      : projection.state === "applied" ? "This change has already been applied."
      : "Reopen your approval email link in this signed-in tab to continue.";
  }

  async function load() {
    const embedded = document.querySelector("#frozen-change");
    if (embedded) render(JSON.parse(embedded.textContent));
    if (token) {
      const located = await api.post("/approvals/locate", {token});
      if (!frozen) render(located);
      history.replaceState(null, "", root + "/review");
    }
  }

  confirm.addEventListener("click", async () => {
    confirm.disabled = true;
    status.textContent = decided ? "Applying the approved change…" : "Waiting for your passkey…";
    try {
      if (!decided) {
        const options = await api.post(root + "/approval-options", {token});
        const assertion = await api.assertion(options);
        await api.post(root + "/approve", {token, assertion});
        decided = true;
        token = "";
        confirm.textContent = "Apply the approved change";
      }
      const result = await api.post(root + "/confirm", {});
      status.dataset.state = "applied";
      status.textContent = result.reauth_required
        ? "Change applied. Sign in again to continue."
        : "1Password service-account token activated.";
      confirm.hidden = true;
      if (result.reauth_required) {
        // No protected result was returned, and no mutation is retried.
        const link = document.createElement("a");
        link.href = "/login?scope=" + encodeURIComponent(document.querySelector("[data-console-scope]").dataset.consoleScope);
        link.textContent = "Sign in with your passkey";
        status.append(document.createTextNode(" "), link);
      }
    } catch {
      if (token && actions && actions.hidden) {
        offerSignIn(inlineLogin());
        return;
      }
      status.dataset.state = decided ? "needs-review" : "pending";
      status.textContent = decided
        ? "Your approval is recorded. Reload this draft to check its status before trying again."
        : "The change was not approved. Check your sign-in and try your passkey again.";
      confirm.disabled = false;
    }
  });

  load().catch(() => {
    if (token && actions && actions.hidden) {
      offerSignIn(inlineLogin());
      return;
    }
    token = "";
    status.textContent = "This approval link is unavailable. Sign in, then reopen the link sent to you.";
    confirm.disabled = true;
  });
})();
