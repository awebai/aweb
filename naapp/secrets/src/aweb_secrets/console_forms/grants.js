"use strict";
(() => {
  const api = window.awebSecretsConsole;
  const form = document.querySelector("#role-grant");
  if (!form) return;
  const status = document.querySelector("#form-status");
  const fields = {
    url: "Enter an exact HTTPS URL without query parameters or wildcards.",
    secret_ref: "Enter the name of an active secret in this team.",
    role: "Enter an owner-defined role, such as secrets.role.deployers.",
    operation_id: "Enter an operation name using lowercase letters, numbers, underscores or hyphens.",
    method: "Choose a supported HTTP method.",
    projection: "Enter distinct JSON pointers, one per line, such as /status.",
    max_bytes: "Enter a response limit from 1 to 16777216 bytes.",
    side_effect: "Choose the operation’s side effect.",
    approval: "Choose the approval requirement.",
    capacity: "Enter a positive whole number of uses per agent.",
    window_s: "Enter a positive whole number of seconds.",
  };
  form.addEventListener("input", event => {
    const control = event.target;
    if (control.matches("input,select,textarea")) {
      control.setCustomValidity("");
      control.removeAttribute("aria-invalid");
      control.removeAttribute("aria-errormessage");
    }
  });
  let submitted = false;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submitted) return;
    submitted = true;
    form.querySelector("button").disabled = true;
    status.textContent = "Saving your access draft…";
    const data = Object.fromEntries(new FormData(form));
    data.projection = data.projection.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    for (const name of ["max_bytes", "capacity", "window_s"]) data[name] = Number(data[name]);
    try {
      const drafted = await api.post(form.action, data);
      const root = "/installations/" + encodeURIComponent(form.dataset.installation) + "/change-sets";
      status.dataset.state = "pending";
      status.textContent = "Access draft saved. Open your approval email to review and confirm it.";
      const link = document.createElement("a");
      link.href = root + "/" + encodeURIComponent(drafted.change_id) + "/review";
      link.textContent = "Review this draft";
      status.append(document.createTextNode(" "), link);
    } catch (error) {
      const detail = error.detail;
      if ([400, 404].includes(error.status) && detail &&
          detail.code === "grant_form_invalid" && detail.draft_created === false &&
          Object.hasOwn(fields, detail.field)) {
        const control = form.elements.namedItem(detail.field);
        status.dataset.state = "invalid";
        status.textContent = fields[detail.field];
        control.setAttribute("aria-invalid", "true");
        control.setAttribute("aria-errormessage", "form-status");
        control.setCustomValidity(fields[detail.field]);
        control.focus();
        submitted = false;
        form.querySelector("button").disabled = false;
        return;
      }
      // A lost response may follow a committed draft. Never replay automatically.
      status.dataset.state = "uncertain";
      status.textContent = "The draft could not be saved. Check your sign-in and approval email before trying again.";
    }
  });
})();
