"use strict";

(() => {
  const form = document.querySelector("#native-value");
  if (!form) return;
  const api = window.awebConsole;
  const status = document.querySelector("#form-status");
  const control = name => form.elements.namedItem(name);
  const read = name => control(name).value;
  const kinds = [...form.querySelectorAll("fieldset[data-kind]")];
  const NativeEntryState = Object.freeze({READY: "ready", SEALING: "sealing", DRAFTING: "drafting", PENDING: "pending", UNCERTAIN: "uncertain"});
  let state = NativeEntryState.READY;

  function selectKind() {
    for (const fields of kinds) {
      fields.hidden = fields.dataset.kind !== read("kind");
      fields.disabled = fields.hidden;
      for (const input of fields.querySelectorAll("[data-value-field]")) input.value = "";
    }
  }
  control("kind").addEventListener("change", selectKind);
  selectKind();
  control("approve_only").addEventListener("change", () => {
    if (control("approve_only").checked) control("sensitivity").value = form.dataset.sensitive;
  });
  control("sensitivity").addEventListener("change", () => {
    if (read("sensitivity") === form.dataset.standard) control("approve_only").checked = false;
  });

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (state !== NativeEntryState.READY) return;
    state = NativeEntryState.SEALING;
    const button = form.querySelector("button");
    button.disabled = true;
    status.textContent = "Sealing the value and saving your draft…";
    const selected = kinds.find(fields => !fields.disabled);
    if (!selected) {
      status.textContent = "Choose an authentication kind before entering the value.";
      state = NativeEntryState.READY;
      button.disabled = false;
      return;
    }
    const valueInputs = [...selected.querySelectorAll("[data-value-field]")];
    const value = Object.fromEntries(valueInputs
      .filter(input => input.value || !input.hasAttribute("data-optional"))
      .map(input => [input.dataset.valueField, input.value]));
    for (const input of valueInputs) input.value = "";
    const secret = {
      v: 1, secret_id: read("secret_id"), ref: read("ref"), description: read("description"),
      kind: read("kind"), sensitivity: read("sensitivity"),
      approve_only: control("approve_only").checked, backend: form.dataset.backend,
      kind_params: Object.fromEntries([...selected.querySelectorAll("[data-param]")]
        .map(input => [input.dataset.param, input.value])),
    };
    try {
      const staged = await api.post(form.action, {secret, value});
      for (const name of Object.keys(value)) value[name] = "";
      if (!staged || staged.secret_id !== secret.secret_id ||
          !Number.isSafeInteger(staged.version) || staged.version < 1 ||
          typeof staged.created_at !== "string" || Number.isNaN(Date.parse(staged.created_at))) {
        throw new Error("The sealing receipt was incomplete.");
      }
      state = NativeEntryState.DRAFTING;
      const root = "/installations/" + encodeURIComponent(form.dataset.installation) + "/change-sets";
      const draft = await api.post(root, {
        changes: [
          {kind: "secret", op: "create", ref: secret.ref, after: secret},
          {kind: "secret_value", op: "create", ref: secret.ref,
            after: {v: 1, secret_ref: secret.ref, version: staged.version}},
        ],
        sealed: [{secret_id: staged.secret_id, version: staged.version}],
        reason: read("reason") || "Store a native secret",
      });
      if (!draft || typeof draft.change_id !== "string" || !draft.change_id) {
        throw new Error("The draft receipt was incomplete.");
      }
      state = NativeEntryState.PENDING;
      status.dataset.state = state;
      status.textContent = "Sealed version " + staged.version + " at " + new Date(staged.created_at).toLocaleString() +
        ". Draft saved. Open your approval email to confirm the value. ";
      const review = document.createElement("a");
      review.href = root + "/" + encodeURIComponent(draft.change_id) + "/review";
      review.textContent = "Review this draft";
      status.append(review);
    } catch (error) {
      const detail = error && typeof error.detail === "string" ? error.detail.trim() : "";
      if (error instanceof api.SessionRequired) {
        state = state === NativeEntryState.DRAFTING ? NativeEntryState.UNCERTAIN : NativeEntryState.READY;
        status.textContent = "Sign in with your passkey in this tab, then enter the value again.";
      } else if (state === NativeEntryState.DRAFTING) {
        state = NativeEntryState.UNCERTAIN;
        const recovery = "The value was sealed, but saving the draft was not confirmed. " +
          "Check your approval email for a link to review it. If none arrived, reload this page " +
          "and enter the value again. Unused sealed copies stay inactive.";
        status.textContent = recovery;
      } else {
        state = NativeEntryState.READY;
        status.textContent = detail || "The value could not be saved. Check your connection and try entering it again.";
      }
      status.dataset.state = state;
    } finally {
      for (const name of Object.keys(value)) value[name] = "";
      for (const input of valueInputs) input.value = "";
      button.disabled = state !== NativeEntryState.READY;
    }
  });
})();
