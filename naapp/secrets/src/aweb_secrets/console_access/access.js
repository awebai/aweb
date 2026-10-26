"use strict";

(() => {
  const notice = document.querySelector("#notice");
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
        if (notice) notice.textContent = "The grant could not be revoked. Try again.";
        button.disabled = false;
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
        if (notice) notice.textContent = "The agent could not be removed from the role. Try again.";
        button.disabled = false;
      }
    });
  }
})();
