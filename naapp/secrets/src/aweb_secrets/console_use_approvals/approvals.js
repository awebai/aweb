"use strict";
(() => {
  const api = window.awebConsole;
  const panel = document.querySelector("#use-approval");
  if (!panel) return;
  const root = panel.dataset.root;
  const status = panel.querySelector("#approval-status");
  const viewButton = panel.querySelector("#view-request");
  const review = panel.querySelector("#request-review");
  let token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  let busy = false;

  function fact(list, name, value) {
    if (value === null || value === undefined) return;
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = name;
    detail.textContent = String(value);
    list.append(term, detail);
  }
  function textBlock(parent, title, value) {
    const heading = document.createElement("h3");
    const text = document.createElement("pre");
    heading.textContent = title;
    text.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    parent.append(heading, text);
  }
  function render(result) {
    const v = result.view;
    const facts = panel.querySelector("#request-facts");
    facts.replaceChildren();
    for (const [label, value] of [
      ["Secret", v.secret_ref], ["Kind", v.secret_kind], ["Version", v.secret_version],
      ["Backend", v.secret_backend], ["Requested by", v.requester_alias],
      ["Agent", v.requester_did], ["Request", v.request_id], ["Grant", v.grant_id],
      ["Policy", v.policy_digest], ["Requested at", v.issued_at], ["Expires", v.expires_at],
    ]) fact(facts, label, value);
    const action = panel.querySelector("#request-action");
    action.replaceChildren();
    if (v.operation) {
      fact(facts, "Operation", v.operation.operation_id);
      fact(facts, "Operation digest", v.operation.operation_digest);
      textBlock(action, "Parameters", v.operation.params);
    }
    if (v.open_request) {
      const r = v.open_request;
      fact(facts, "Method", r.method);
      fact(facts, "Host (Unicode)", r.host_unicode);
      fact(facts, "Host (A-label)", r.host);
      const url = document.createElement("p");
      const host = document.createElement("strong");
      host.textContent = r.host;
      url.append(document.createTextNode(r.url_before_host), host, document.createTextNode(r.url_after_host));
      action.append(url);
      fact(facts, "Header names", r.header_names.join(", "));
      textBlock(action, "Complete request body", r.body_text);
    }
    if (v.job) {
      const j = v.job;
      fact(facts, "Runner", j.runner_id);
      fact(facts, "Job", j.job_id);
      fact(facts, "Job digest", j.job_digest);
      fact(facts, "Credential delivery", j.credential_delivery);
      fact(facts, "Credential slot", j.slot_ordinal);
      fact(facts, "Frozen plan digest", j.plan_digest);
      if (j.credential_delivery === "durable") {
        const warning = document.createElement("p");
        const strong = document.createElement("strong");
        strong.textContent = "This releases a durable credential to this runner for the approved job.";
        warning.append(strong);
        action.append(warning);
      }
      textBlock(action, "Job parameters", j.params);
      if (j.frozen_plan) textBlock(action, "Frozen job and credential slots", j.frozen_plan);
      if (j.mint_params) textBlock(action, "Credential operation parameters", j.mint_params);
      if (j.child_grant_template) textBlock(action, "Resulting credential grant", j.child_grant_template);
    }
    panel.querySelector("#request-reason").textContent = v.untrusted_reason;
    review.hidden = false;
    viewButton.hidden = true;
    status.textContent = "Review the full request before approving or rejecting it.";
  }

  async function signin() {
    const hint = await api.post(root + "/sign-in", {token});
    const options = await api.post("/login/options", {scope: hint.scope});
    const assertion = await api.assertion(options);
    const logged = await api.post("/login", {scope: hint.scope, assertion});
    sessionStorage.setItem(api.csrfKey, logged.csrf_token);
    history.replaceState(null, "", root + "#token=" + encodeURIComponent(token));
    location.reload();
  }
  const scoped = document.querySelector("[data-console-scope]");
  function needsLogin() { return !scoped || scoped.hidden; }
  let loginButton;
  function offerLogin() {
    if (loginButton) return;
    const notice = document.querySelector("#console-reauth-notice") || panel;
    const ordinary = document.querySelector("#console-reauth");
    if (ordinary) ordinary.hidden = true;
    loginButton = document.createElement("button");
    loginButton.type = "button";
    loginButton.textContent = "Sign in with your passkey";
    const feedback = document.createElement("p");
    feedback.setAttribute("role", "status");
    loginButton.addEventListener("click", async () => {
      loginButton.disabled = true;
      try { await signin(); }
      catch {
        feedback.textContent = "Sign-in could not be completed. Reopen your approval email if the link has expired.";
        loginButton.disabled = false;
      }
    });
    notice.append(loginButton, feedback);
  }
  if (!token) return;
  if (needsLogin()) { offerLogin(); viewButton.hidden = true; return; }
  viewButton.disabled = false;
  status.textContent = "Use your passkey to view the request sent to you.";
  viewButton.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    viewButton.disabled = true;
    try {
      const options = await api.post(root + "/view-options", {token});
      const assertion = await api.assertion(options);
      render(await api.post(root + "/view", {token, assertion}));
    } catch {
      status.textContent = "The request could not be opened. Check your sign-in or reopen the approval email.";
      if (needsLogin()) offerLogin();
      viewButton.disabled = false;
    } finally { busy = false; }
  });
  for (const decision of ["approve", "reject"]) {
    panel.querySelector("#" + decision + "-request").addEventListener("click", async () => {
      if (busy) return;
      busy = true;
      const buttons = review.querySelectorAll("button");
      buttons.forEach(button => { button.disabled = true; });
      try {
        const options = await api.post(root + "/decision-options", {token, decision});
        const assertion = await api.assertion(options);
        const result = await api.post(root + "/decide", {token, decision, assertion});
        token = "";
        panel.dataset.state = result.state;
        panel.dataset.approvalId = result.approval_id;
        status.textContent = result.state === "approved"
          ? "Approved. The agent can resubmit this request to continue."
          : "Rejected. This request cannot use the credential.";
        buttons.forEach(button => { button.hidden = true; });
      } catch {
        // A lost response can follow a committed decision. Never replay it.
        status.textContent = "The decision could not be confirmed. Check the request status with the requesting agent before trying again.";
        if (needsLogin()) offerLogin();
      } finally { busy = false; }
    });
  }
})();
