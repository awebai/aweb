"use strict";
(() => {
  const api = window.awebSecretsConsole;
  const form = document.querySelector("#role-grant");
  if (!form) return;
  const status = document.querySelector("#form-status");
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
    } catch {
      // A lost response may follow a committed draft. Never replay automatically.
      status.textContent = "The draft could not be saved. Check your sign-in and approval email before trying again.";
    }
  });
})();
