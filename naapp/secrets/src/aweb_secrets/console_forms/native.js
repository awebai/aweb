"use strict";

(() => {
  const form = document.querySelector("#native-value");
  if (!form) return;
  const api = window.awebConsole;
  const status = document.querySelector("#form-status");
  const control = name => form.elements.namedItem(name);
  const read = name => control(name).value;
  const kinds = [...form.querySelectorAll("fieldset[data-kind]")];
  const NativeEntryState = Object.freeze({READY: "ready", SEALING: "sealing", DRAFTING: "drafting", PENDING: "pending"});
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
      status.textContent = "Sealed version " + staged.version + " at " + staged.created_at +
        ". Draft saved. Open your approval email to confirm the value. ";
      const review = document.createElement("a");
      review.href = root + "/" + encodeURIComponent(draft.change_id) + "/review";
      review.textContent = "Review this draft";
      status.append(review);
    } catch (error) {
      const action = state === NativeEntryState.DRAFTING
        ? " Check your pending drafts before entering the value again."
        : " Sign in as the owner and enter the value again when ready.";
      status.textContent = error instanceof Error && error.message
        ? error.message + action
        : "The draft could not be saved. Sign in as the owner and enter the value again.";
      state = NativeEntryState.READY;
    } finally {
      for (const name of Object.keys(value)) value[name] = "";
      for (const input of valueInputs) input.value = "";
      button.disabled = state !== NativeEntryState.READY;
    }
  });
})();
