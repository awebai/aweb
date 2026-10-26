"use strict";
(() => {
  const api = window.awebSecretsConsole;
  const status = document.querySelector("#reconciliation-status");
  if (!status) return;
  const root = "/reconciliation-approvals";
  let token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  const scoped = document.querySelector("[data-console-scope]");
  const needsLogin = () => !scoped || scoped.hidden;
  function message(text) { status.textContent = text; status.focus(); }
  function fact(list, label, value) {
    if (value === undefined || value === null) return;
    const term = document.createElement("dt"), detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = String(value);
    list.append(term, detail);
  }
  const review = document.querySelector("#outcome-review");
  const view = document.querySelector("#view-outcome");
  const link = document.querySelector("#settlement-link");
  function statusLink(id) {
    link.href = "/reconciliation-controls/" + encodeURIComponent(id);
    link.hidden = false;
  }
  if (needsLogin() && (token || scoped)) {
    const notice = document.querySelector("#console-reauth-notice") || status.parentElement;
    const ordinary = document.querySelector("#console-reauth");
    if (ordinary) ordinary.hidden = true;
    const login = document.createElement("button");
    login.type = "button";
    login.textContent = "Sign in with your passkey";
    login.addEventListener("click", async () => {
      login.disabled = true;
      try {
        const hint = token ? await api.post(root + "/sign-in", {token}) : {scope: scoped.dataset.consoleScope};
        const options = await api.post("/login/options", {scope: hint.scope});
        const logged = await api.post("/login", {scope: hint.scope, assertion: await api.assertion(options)});
        sessionStorage.setItem("aweb.secrets.console.csrf", logged.csrf_token);
        if (token) history.replaceState(null, "", root + "#token=" + encodeURIComponent(token));
        location.reload();
      } catch { message("Sign-in could not be completed. Reopen your personal link if it has expired."); login.disabled = false; }
    });
    notice.append(login);
    if (view) view.hidden = true;
    return;
  }
  const choice = document.querySelector("#reconciliation-choice");
  if (choice) choice.addEventListener("submit", async event => {
    event.preventDefault();
    const button = choice.querySelector("button");
    if (button.disabled) return;
    button.disabled = true;
    try {
      const result = await api.post(choice.getAttribute("action"), {outcome: choice.elements.outcome.value});
      location.assign(root + "#token=" + encodeURIComponent(result.personal_token));
    } catch { message("The review could not be confirmed. Check the original record and your approval delivery before starting another review."); }
  });
  const settle = document.querySelector("#settle-outcome");
  if (settle) settle.addEventListener("click", async () => {
    if (settle.disabled) return;
    settle.disabled = true;
    try {
      const result = await api.post(settle.dataset.endpoint, {});
      const receipt = document.querySelector("#settlement-receipt");
      for (const [label, value] of [["State", result.state], ["Request reference", result.reconcile_ref],
        ["Request ID", result.request_id], ["Dispatch ID", result.dispatch_id], ["Approval ID", result.control_approval_id]]) fact(receipt, label, value);
      receipt.dataset.state = result.state;
      message("Settlement recorded. The original operation is closed.");
      settle.hidden = true;
    } catch { message("Settlement could not be confirmed. Reload this status page before taking another action."); }
  });
  if (!view || !token) return;
  view.disabled = false;
  view.addEventListener("click", async () => {
    if (view.disabled) return;
    view.disabled = true;
    try {
      const options = await api.post(root + "/view-options", {token});
      const result = await api.post(root + "/view", {token, assertion: await api.assertion(options)});
      const control = result.control, original = control.original;
      const facts = document.querySelector("#outcome-facts");
      facts.replaceChildren();
      for (const [label, value] of [["Chosen outcome", control.outcome], ["Request reference", original.reconcile_ref],
        ["Request ID", original.request_id], ["Agent", original.requested_by], ["Dispatch ID", original.dispatch_id],
        ["Operation", original.operation_id], ["Operation digest", original.operation_digest],
        ["Job", original.job_id], ["Job digest", original.job_digest], ["Runner", original.runner_id],
        ["Installation generation", original.installation.generation],
        ["Expires", control.expires_at]]) fact(facts, label, value);
      for (const resource of original.resources) fact(facts, "Secret version", (resource.secret_ref || resource.secret_id) + " · " + resource.version);
      statusLink(control.approval_id);
      review.hidden = false;
      message("Review the chosen outcome, then use a fresh passkey tap to approve or reject it.");
      view.hidden = true;
    } catch { message("This review could not be opened. Check your sign-in or reopen the personal approval link."); view.disabled = false; }
  });
  for (const decision of ["approve", "reject"]) {
    const button = document.querySelector("#" + decision + "-outcome");
    button.addEventListener("click", async () => {
      if (button.disabled) return;
      const buttons = review.querySelectorAll("button");
      buttons.forEach(b => { b.disabled = true; });
      let submitted = false;
      try {
        const options = await api.post(root + "/decision-options", {token, decision});
        const assertion = await api.assertion(options);
        submitted = true;
        const result = await api.post(root + "/decide", {token, decision, assertion});
        token = "";
        statusLink(result.approval_id);
        message(result.state === "approved" ? "Approved. Continue to settlement status to confirm the outcome." : "Rejected. The original record remains unchanged.");
        buttons.forEach(b => { b.hidden = true; });
        link.focus();
      } catch {
        message(submitted ? "The decision could not be confirmed. Check settlement status before taking another action." : "The passkey step was not completed. You can try it again.");
        if (!submitted) buttons.forEach(b => { b.disabled = false; });
      }
    });
  }
})();
