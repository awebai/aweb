import { element } from "./dom.mjs";
import { inputErrors, typedValue, acceptableFile } from "./input.mjs";

const errorText = (error) =>
  ({
    revision_conflict:
      "This page changed while you were editing. Your draft is kept.",
    idempotency_conflict: "This request conflicts with an earlier submission.",
    action_denied: "You cannot perform this action.",
    scope_denied: "You cannot perform this action.",
    csrf_required: "The host could not verify this request. Refresh the page.",
    approval_required: "Verified human approval is required.",
    schema_invalid: "Check the highlighted fields.",
    unavailable: "The service is unavailable. Your draft is kept.",
  })[error?.code] ||
  "The outcome is unknown. Check the request before trying again.";
export function receiptText(receipt) {
  if (receipt?.transaction_id) return "Saved";
  if (receipt?.attachment_id) return `Uploaded · ${receipt.attachment_id}`;
  if (receipt?.delivery === "queued")
    return "Queued for the agent. Execution not started.";
  if (receipt?.delivery === "pending")
    return "Request recorded · delivery pending. Execution not started.";
  return "Request recorded";
}

export function createActions({ host, getPage, update, announce }) {
  const keys = new Map();
  let authorityEpoch = 0;
  function policy(actionId, context = {}) {
    return (
      host.actionPolicy?.(actionId, context) || {
        allowed: false,
        reason: "This action is unavailable.",
      }
    );
  }
  async function csrf() {
    const boundary = authorityEpoch;
    const token = await host.csrfToken?.();
    if (boundary !== authorityEpoch || !getPage())
      throw { code: "action_denied" };
    if (typeof token !== "string" || !token) throw { code: "csrf_required" };
    return { csrfToken: token };
  }
  async function fileDigest(file) {
    const bytes = await crypto.subtle.digest(
      "SHA-256",
      await file.arrayBuffer(),
    );
    return (
      "sha256:" +
      Array.from(new Uint8Array(bytes), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("")
    );
  }
  function requestFor(w, actionId, input, record, baseRev) {
    const page = getPage();
    if (!page) throw { code: "action_denied" };
    const request = {
      page_id: page.page_id,
      widget_id: w.id,
      action_id: actionId,
      expected_page_rev: baseRev ?? page.rev,
      input,
    };
    if (record) {
      request.collection = w.bind.collection;
      request.record_id = record.id;
      request.expected_record_rev = record.rev;
    }
    const identity = JSON.stringify(request);
    if (!keys.has(identity)) keys.set(identity, crypto.randomUUID());
    return { ...request, idempotency_key: keys.get(identity) };
  }
  async function invoke(
    w,
    actionId,
    input,
    event,
    { record, baseRev, files = [] } = {},
  ) {
    if (!event?.isTrusted) throw { code: "action_denied" };
    const page = getPage(),
      action = page?.actions.find((a) => a.id === actionId),
      admission = policy(actionId, { widget_id: w.id, record });
    if (
      !action ||
      action.kind === "answer" ||
      !admission.allowed ||
      !host.invoke
    )
      throw { code: "action_denied" };
    if (
      admission.consequential ||
      w.props?.confirmation ||
      action.requires_approval
    ) {
      if (
        !host.confirmAction ||
        !(await host.confirmAction(
          {
            label: admission.label || action.label,
            description:
              admission.description ||
              w.props?.confirmation ||
              action.operation ||
              "",
          },
          event,
        ))
      )
        return null;
    }
    const values = { ...input };
    for (const { field, file } of files) {
      if (!host.upload) throw { code: "unavailable" };
      const request = requestFor(
        w,
        actionId,
        {
          field_id: field.id,
          name: file.name,
          mime: file.type,
          size: file.size,
          file_sha256: await fileDigest(file),
        },
        record,
        baseRev,
      );
      const receipt = await host.upload({ ...request, file }, await csrf());
      if (
        !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(
          receipt?.attachment_id || "",
        )
      )
        throw { code: "schema_invalid" };
      values[field.id] = receipt.attachment_id;
    }
    const errors = inputErrors(values, action.input_schema);
    if (errors.length) throw { code: "schema_invalid", pointers: errors };
    return host.invoke(
      requestFor(w, actionId, values, record, baseRev),
      await csrf(),
    );
  }
  function feedback(box) {
    const error = element("p", null, "field-error");
    error.setAttribute("role", "alert");
    error.hidden = true;
    const status = element("p", null, "action-status");
    status.setAttribute("role", "status");
    const recovery = element("div", null, "conflict-recovery");
    box.append(error, status, recovery);
    return { error, status, recovery };
  }
  function showError(ui, error, onRebase) {
    ui.error.hidden = false;
    ui.error.textContent = errorText(error);
    ui.recovery.replaceChildren();
    if (error?.code === "revision_conflict" && host.refresh) {
      const refresh = element("button", "Review current page");
      refresh.type = "button";
      refresh.onclick = async () => {
        try {
          const page = await host.refresh();
          if (!getPage()) return;
          update(page);
          ui.recovery.replaceChildren();
          const reapply = element("button", "Use current page revision");
          reapply.type = "button";
          reapply.onclick = () => {
            onRebase?.(page.rev);
            ui.error.hidden = true;
            ui.recovery.replaceChildren();
            announce("Draft retained. Review it before submitting again.");
          };
          ui.recovery.append(
            element(
              "p",
              "Your draft is unchanged. Review the current page before reapplying it.",
            ),
            reapply,
          );
        } catch (error) {
          ui.error.textContent = errorText(error);
        }
      };
      ui.recovery.append(refresh);
    }
    announce(ui.error.textContent);
  }
  function actionButton(w, actionId, record, label) {
    const action = getPage()?.actions.find((a) => a.id === actionId),
      admission = policy(actionId, { widget_id: w.id, record });
    const button = element("button", label || action?.label || "Action");
    button.type = "button";
    button.dataset.focusKey = `action:${actionId}:${record?.id || ""}`;
    const fixed = {
      ...(admission.input || {}),
      ...(record ? { record_id: record.id } : {}),
    };
    button.disabled =
      !admission.allowed ||
      !action ||
      action.kind === "answer" ||
      inputErrors(fixed, action?.input_schema).length > 0;
    button.title = button.disabled
      ? admission.reason || "This action needs more information."
      : action?.label || "";
    let pending = false,
      feedbackBox;
    button.onclick = async (event) => {
      if (pending) return;
      pending = true;
      button.disabled = true;
      feedbackBox?.remove();
      const box = element("div", null, "action-feedback");
      feedbackBox = box;
      button.after(box);
      const ui = feedback(box);
      ui.status.textContent = "Submitting…";
      try {
        const receipt = await invoke(w, actionId, fixed, event, { record });
        if (receipt) {
          ui.status.textContent = receiptText(receipt);
          announce(ui.status.textContent);
        }
      } catch (error) {
        ui.status.textContent = "";
        showError(ui, error);
      } finally {
        pending = false;
        button.disabled = !policy(actionId, { widget_id: w.id, record })
          .allowed;
      }
    };
    return button;
  }
  function form(box, w) {
    const p = w.props,
      action = getPage().actions.find((a) => a.id === p.submit_action);
    const node = element("form", null, "page-form");
    node.noValidate = true;
    node.setAttribute("aria-label", action.label);
    const controls = new Map();
    let baseRev,
      pending = false;
    for (const field of p.fields) {
      const group = element("div", null, "form-field");
      const label = element("label", field.label);
      const id = `field-${w.id}-${field.id}`;
      label.htmlFor = id;
      let input;
      if (field.kind === "select") {
        input = element("select");
        for (const option of field.options) {
          const item = element("option", option.label);
          item.value = option.value;
          input.append(item);
        }
      } else {
        input = element("input");
        input.type =
          field.kind === "number"
            ? "text"
            : field.kind === "file"
              ? "file"
              : field.kind === "checkbox"
                ? "checkbox"
                : field.kind === "date"
                  ? "date"
                  : "text";
      }
      input.id = id;
      input.name = field.id;
      input.dataset.focusKey = `field:${field.id}`;
      const required =
        field.required || action.input_schema.required?.includes(field.id);
      input.required = !!required;
      if (field.kind === "number")
        input.inputMode =
          action.input_schema.properties?.[field.id]?.type === "integer"
            ? "numeric"
            : "decimal";
      if (field.kind === "file") input.accept = field.accept.join(",");
      const initial = action.input_schema.properties?.[field.id]?.default;
      if (field.kind === "checkbox") input.checked = initial === true;
      else if (
        initial !== undefined &&
        ["string", "number"].includes(typeof initial)
      )
        input.value = String(initial);
      input.addEventListener("input", () => {
        baseRev ??= getPage()?.rev;
      });
      input.addEventListener("change", () => {
        baseRev ??= getPage()?.rev;
      });
      const error = element("p", null, "field-error");
      error.id = `${id}-error`;
      error.hidden = true;
      input.setAttribute("aria-describedby", `${id}-description ${error.id}`);
      const description = element(
        "p",
        field.description || "",
        "field-description",
      );
      description.id = `${id}-description`;
      group.append(label, input, description, error);
      node.append(group);
      controls.set(field.id, { field, input, error });
    }
    const submit = element("button", action.label);
    submit.type = "submit";
    submit.disabled = !policy(action.id, { widget_id: w.id }).allowed;
    node.append(submit);
    const ui = feedback(node);
    box.append(node);
    node.onsubmit = async (event) => {
      event.preventDefault();
      if (pending || !event.isTrusted) return;
      ui.error.hidden = true;
      ui.status.textContent = "";
      ui.recovery.replaceChildren();
      const values = {},
        files = [];
      let invalid;
      for (const { field, input, error } of controls.values()) {
        error.hidden = true;
        input.removeAttribute("aria-invalid");
        const property = getPage().actions.find((a) => a.id === action.id)
          ?.input_schema.properties?.[field.id];
        let message;
        if (field.kind === "file") {
          if (input.files[0]) {
            message = acceptableFile(
              input.files[0],
              field.accept,
              field.max_bytes,
            );
            files.push({ field, file: input.files[0] });
          } else if (input.required) message = "Choose a file.";
        } else {
          const value =
            field.kind === "checkbox"
              ? input.checked
              : field.kind === "number" || field.kind === "select"
                ? typedValue(input.value, property)
                : input.value;
          if (
            input.required &&
            ((field.kind === "checkbox" && !value) || value === "")
          )
            message = "Complete this field.";
          else if (value === undefined || inputErrors(value, property).length)
            message = "Enter a valid value for this field.";
          values[field.id] = value;
        }
        if (message) {
          error.hidden = false;
          error.textContent = message;
          input.setAttribute("aria-invalid", "true");
          invalid ??= input;
        }
      }
      if (invalid) {
        ui.error.hidden = false;
        ui.error.textContent = "Check the highlighted fields.";
        invalid.focus();
        return;
      }
      pending = true;
      submit.disabled = true;
      node.setAttribute("aria-busy", "true");
      ui.status.textContent = "Submitting…";
      try {
        const receipt = await invoke(w, action.id, values, event, {
          baseRev,
          files,
        });
        if (receipt) {
          ui.status.textContent = receiptText(receipt);
          announce(ui.status.textContent);
          baseRev = receipt.page_rev ?? getPage()?.rev;
        }
      } catch (error) {
        ui.status.textContent = "";
        showError(ui, error, (revision) => {
          baseRev = revision;
        });
        for (const pointer of error?.pointers || []) {
          const field = controls.get(pointer.slice(1));
          if (field) {
            field.error.hidden = false;
            field.error.textContent = "Check this field.";
            field.input.setAttribute("aria-invalid", "true");
          }
        }
      } finally {
        pending = false;
        node.setAttribute("aria-busy", "false");
        submit.disabled = !policy(action.id, { widget_id: w.id }).allowed;
      }
    };
  }
  function fileDrop(box, w) {
    const p = w.props,
      node = element("form", null, "file-drop");
    node.noValidate = true;
    const label = element("label", p.label);
    const input = element("input");
    input.type = "file";
    input.id = `upload-${w.id}`;
    label.htmlFor = input.id;
    input.accept = p.accept.join(",");
    const selected = element(
      "p",
      `Allowed: ${p.accept.join(", ")} · up to ${p.max_bytes.toLocaleString("en")} bytes`,
      "field-description",
    );
    const submit = element("button", "Upload");
    submit.type = "submit";
    submit.disabled = !policy(p.action, { widget_id: w.id }).allowed;
    let file,
      pending = false;
    input.onchange = () => {
      file = input.files[0];
      selected.textContent = file?.name || "Choose a file.";
    };
    node.ondragover = (event) => event.preventDefault();
    node.ondrop = (event) => {
      event.preventDefault();
      file = event.dataTransfer.files[0];
      selected.textContent = file?.name || "Choose a file.";
    };
    node.append(label, input, selected, submit);
    const ui = feedback(node);
    box.append(node);
    node.onsubmit = async (event) => {
      event.preventDefault();
      if (pending || !event.isTrusted) return;
      const message = acceptableFile(file, p.accept, p.max_bytes);
      if (message) {
        ui.error.hidden = false;
        ui.error.textContent = message;
        return;
      }
      if (!policy(p.action, { widget_id: w.id }).allowed || !host.upload) {
        showError(ui, { code: "action_denied" });
        return;
      }
      pending = true;
      submit.disabled = true;
      node.setAttribute("aria-busy", "true");
      ui.status.textContent = "Uploading…";
      ui.error.hidden = true;
      try {
        const receipt = await host.upload(
          {
            ...requestFor(w, p.action, {
              name: file.name,
              mime: file.type,
              size: file.size,
              file_sha256: await fileDigest(file),
            }),
            file,
          },
          await csrf(),
        );
        if (
          !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(
            receipt?.attachment_id || "",
          )
        )
          throw { code: "schema_invalid" };
        ui.status.textContent = receiptText(receipt);
        announce(ui.status.textContent);
      } catch (error) {
        showError(ui, error);
      } finally {
        pending = false;
        node.setAttribute("aria-busy", "false");
        submit.disabled = !policy(p.action, { widget_id: w.id }).allowed;
      }
    };
  }
  return {
    form,
    fileDrop,
    actionButton,
    clear() {
      authorityEpoch++;
      keys.clear();
    },
    csrf,
    requestFor,
    policy,
    showError,
    feedback,
  };
}
