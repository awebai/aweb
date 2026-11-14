// The owner page's "Remove…": asks the signer to prepare an owner-approved
// removal of one member, then opens its approval page, where nothing happens
// until the owner approves that exact act with their passkey.
//
// The selection is saved in this tab before it is sent, under this team and
// this signed-in approver, and a retry sends exactly the same request. No
// answer from the prepare route proves that nothing was prepared, so no error
// clears it; only a final entry for its operation in this page's History does
// (human-assurance-contract.md, owner-session initiation).
(() => {
  const list = document.getElementById("owner-members");
  const status = document.getElementById("owner-remove-status");
  if (!list || !status) return;
  const team = list.dataset.teamId;
  const prefix = `aweb.owner-removal:${list.dataset.storageScope}:`;

  function saved(key) {
    try {
      return JSON.parse(sessionStorage.getItem(key));
    } catch {
      return null;
    }
  }

  const final = new Set();
  for (const item of document.querySelectorAll("[data-final-operation]")) final.add(item.dataset.finalOperation);
  const keys = [];
  for (let index = 0; index < sessionStorage.length; index++) keys.push(sessionStorage.key(index));
  for (const key of keys) {
    if (key && key.startsWith(prefix) && final.has(saved(key)?.operation_id)) sessionStorage.removeItem(key);
  }

  const refusals = {
    subject_ineligible: "The signer will not remove this member on an owner's approval.",
    authority_changed: "The team's signing key or approvers changed.",
    scope_refused: "This request was started by another approver or team.",
    receipt_unavailable: "The signer could not answer right now.",
  };

  function selection(certificate) {
    const key = prefix + certificate;
    const kept = saved(key);
    if (kept && kept.team_id === team && kept.certificate_id === certificate &&
        typeof kept.operation_id === "string" && kept.operation_id) return kept;
    const chosen = {operation_id: crypto.randomUUID(), operation: "team.agent.remove",
      variant: "owner_approved", team_id: team, certificate_id: certificate};
    sessionStorage.setItem(key, JSON.stringify(chosen));
    return chosen;
  }

  for (const button of list.querySelectorAll("[data-remove-certificate]")) {
    button.addEventListener("click", async () => {
      const chosen = selection(button.dataset.removeCertificate);
      button.disabled = true;
      status.textContent = "Preparing the removal request…";
      try {
        const result = await window.awebConsole.post("/governance/operations", chosen);
        if (typeof result.handoff_id !== "string" || !result.handoff_id) throw new Error("unconfirmed");
        window.location.assign("/handoff/" + encodeURIComponent(result.handoff_id));
      } catch (error) {
        // The signer stored this request's expiry as final; reloading shows
        // it in History, which lets this tab start a new request.
        if (error?.detail === "operation_expired") {
          status.textContent = "This request expired without being carried out. Reload to request a new approval.";
          button.disabled = false;
          return;
        }
        const reason = refusals[error?.detail];
        status.textContent = (reason ? reason + " " : "") +
          "The request was not confirmed. Nothing is removed until you approve it on its page. " +
          "Trying again sends the same request.";
        button.disabled = false;
      }
    });
  }
})();
