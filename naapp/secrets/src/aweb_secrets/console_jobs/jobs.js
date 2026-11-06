"use strict";
(() => {
  const form = document.querySelector("#definition-draft");
  if (!form) return;
  const api = window.awebSecretsConsole;
  const status = document.querySelector("#job-status");
  const button = form.querySelector("button");
  const value = name => document.getElementById(name).value.trim();
  const json = name => JSON.parse(value(name));
  const list = name => [...new Set(value(name).split(",").map(s => s.trim()).filter(Boolean))].sort();
  let submitted = false;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submitted) return;
    let after;
    try {
      after = form.dataset.kind === "runner" ? {
        v: 1, runner_id: value("runner-id"), label: value("runner-label"), allowed_jobs: list("allowed-jobs"),
      } : {
        v: 1, job_id: value("job-id"), runner_ids: list("runner-ids"), kind: "exec",
        exec: {path: value("exec-path"), sha256: value("exec-digest"), files: json("files")},
        oci: null, argv: json("argv"), env: json("env"), cwd: value("cwd"),
        timeout_s: Number(value("timeout")),
        output: {max_bytes: Number(value("output-bytes")), projection: json("projection")},
        params: json("params"), credentials: json("credentials"),
        allow_durable: document.querySelector("#allow-durable").checked,
      };
    } catch {
      status.textContent = "Check the JSON fields. The draft has not been submitted.";
      return;
    }
    submitted = true;
    button.disabled = true;
    status.textContent = "Saving the draft…";
    try {
      const result = await api.post(form.action, {
        changes: [{kind: form.dataset.kind, op: "create", ref: after.job_id || after.runner_id, after}],
        sealed: [], reason: value("reason"),
      });
      status.dataset.state = "pending";
      status.dataset.changeId = result.change_id;
      status.textContent = "Draft saved. Open your approval email to confirm it.";
      const link = document.createElement("a");
      link.href = form.action + "/" + encodeURIComponent(result.change_id) + "/review";
      link.textContent = "Review this draft";
      status.append(document.createTextNode(" "), link);
      // Navigation carries an inert ID only. No registration code is available
      // until the canonical review page commits the passkey-confirmed change.
      location.assign(link.href);
    } catch {
      // Draft creation may have committed before a response was lost. Do not
      // submit it again automatically or persist the definition in storage.
      status.textContent = "The draft could not be confirmed. Check your approval email before submitting another draft.";
    }
  });
})();
