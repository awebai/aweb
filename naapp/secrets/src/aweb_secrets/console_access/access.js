"use strict";

(() => {
  // A failure is reported beside the control that failed, which keeps the focus.
  const failed = (button, message) => {
    const actions = button.closest(".access-actions");
    let alert = actions.previousElementSibling;
    if (!alert || !alert.classList.contains("access-failure")) {
      alert = document.createElement("p");
      alert.className = "access-failure";
      alert.setAttribute("role", "alert");
      actions.before(alert);
    }
    alert.textContent = message;
    button.disabled = false;
    alert.scrollIntoView({block: "nearest"});
    button.focus();
  };
  // Revoking narrows authority, so it needs the S4 session and CSRF only, never a passkey.
  for (const button of document.querySelectorAll(".access-revoke")) {
    button.addEventListener("click", async () => {
      if (!window.confirm(button.textContent + "?")) return;
      button.disabled = true;
      try {
        await window.awebSecretsConsole.post(
          `/installations/${encodeURIComponent(button.dataset.installationId)}/containment`,
          {request_id: crypto.randomUUID(), action: "revoke-grant", target: button.dataset.grantId},
        );
        window.location.reload();
      } catch {
        failed(button, "The grant could not be revoked. Try again.");
      }
    });
  }
  // Removing one agent from an owner-defined role narrows only that agent's access.
  for (const button of document.querySelectorAll(".access-remove-member")) {
    button.addEventListener("click", async () => {
      if (!window.confirm(button.textContent + "?")) return;
      button.disabled = true;
      try {
        await window.awebSecretsConsole.post(
          `/installations/${encodeURIComponent(button.dataset.installationId)}/containment`,
          {
            request_id: crypto.randomUUID(), action: "remove-role-member",
            target: button.dataset.role, principal: button.dataset.principalDid,
          },
        );
        window.location.reload();
      } catch {
        failed(button, "The agent could not be removed from the role. Try again.");
      }
    });
  }
})();
