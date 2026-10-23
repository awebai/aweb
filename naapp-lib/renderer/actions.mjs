import { element, chrome } from "./dom.mjs";
import {
  inputErrors,
  typedValue,
  acceptableFile,
  fileTypes,
  fileSize,
  fieldError,
  fieldValueText,
} from "./input.mjs";

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
  if (receipt?.attachment_id) return "Uploaded";
  if (receipt?.delivery === "queued")
    return "Request saved. Waiting for the agent to pick it up.";
  if (receipt?.delivery === "pending")
    return "Request saved. Waiting for the agent to pick it up.";
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
  function capture(w, actionId, record, baseRev) {
    const page = getPage(),
      action = page?.actions.find((a) => a.id === actionId);
    if (
      !page ||
      !action ||
      !policy(actionId, { widget_id: w.id, record }).allowed
    )
      throw { code: "action_denied" };
    return {
      epoch: authorityEpoch,
      page_id: page.page_id,
      page_rev: baseRev ?? page.rev,
      widget_id: w.id,
      action_id: actionId,
      action: structuredClone(action),
      record: record ? structuredClone(record) : undefined,
      collection: w.bind?.collection,
    };
  }
  function assertCurrent(context) {
    const page = getPage();
    if (
      !context ||
      context.epoch !== authorityEpoch ||
      context.page_id !== page?.page_id
    )
      throw { code: "authority_changed", silent: true };
    const action = page.actions.find((a) => a.id === context.action_id);
    if (
      JSON.stringify(action) !== JSON.stringify(context.action) ||
      !policy(context.action_id, {
        widget_id: context.widget_id,
        record: context.record,
      }).allowed
    )
      throw { code: "action_denied" };
  }
  async function csrf(context) {
    assertCurrent(context);
    const token = await host.csrfToken?.();
    assertCurrent(context);
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
  function requestFor(context, input) {
    assertCurrent(context);
    const request = {
      page_id: context.page_id,
      widget_id: context.widget_id,
      action_id: context.action_id,
      expected_page_rev: context.page_rev,
      input,
    };
    if (context.record)
      request.expected_record_revs = {
        [`${context.collection}/${context.record.id}`]: context.record.rev,
      };
    const identity = JSON.stringify(request);
    if (!keys.has(identity)) keys.set(identity, crypto.randomUUID());
    return { ...request, idempotency_key: keys.get(identity) };
  }
  async function invoke(
    w,
    actionId,
    input,
    event,
    {
      record,
      baseRev,
      files = [],
      context = capture(w, actionId, record, baseRev),
    } = {},
  ) {
    if (!event?.isTrusted || context.action.kind === "answer" || !host.invoke)
      throw { code: "action_denied" };
    assertCurrent(context);
    const action = context.action,
      admission = policy(actionId, { widget_id: w.id, record: context.record });
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
      assertCurrent(context);
    }
    const values = { ...input };
    for (const { field, file } of files) {
      assertCurrent(context);
      if (!host.upload) throw { code: "unavailable" };
      const digest = await fileDigest(file);
      assertCurrent(context);
      const request = requestFor(context, {
        field_id: field.id,
        name: file.name,
        mime: file.type,
        size: file.size,
        file_sha256: digest,
      });
      const credential = await csrf(context);
      assertCurrent(context);
      const receipt = await host.upload({ ...request, file }, credential);
      assertCurrent(context);
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
    const request = requestFor(context, values),
      credential = await csrf(context);
    assertCurrent(context);
    context.submittedInput = structuredClone(values);
    const receipt = await host.invoke(request, credential);
    assertCurrent(context);
    return receipt;
  }
  function feedback(box) {
    const error = chrome("p", null, "field-error");
    error.setAttribute("role", "alert");
    error.hidden = true;
    const status = chrome("p", null, "action-status");
    status.setAttribute("role", "status");
    const recovery = element("div", null, "conflict-recovery");
    box.append(error, status, recovery);
    return { error, status, recovery };
  }
  function restoreFocus(control, message, context) {
    try {
      assertCurrent(context);
    } catch {
      return;
    }
    const target =
      control?.isConnected && !control.disabled && !control.hidden
        ? control
        : message;
    if (!target?.isConnected) return;
    if (target !== control) target.tabIndex = -1;
    target.focus({ preventScroll: true });
  }
  function initialize(button, ui, w, actionId, record) {
    button.disabled = true;
    let context;
    try {
      context = capture(w, actionId, record);
    } catch {
      return;
    }
    csrf(context)
      .then(() => {
        if (button.isConnected) button.disabled = false;
      })
      .catch((error) => {
        if (!error.silent && button.isConnected) {
          ui.error.hidden = false;
          ui.error.textContent = errorText(error);
        }
      });
  }
  async function showError(ui, error, recovery, context) {
    if (error?.silent) return;
    ui.error.hidden = false;
    ui.error.textContent = errorText(error);
    ui.recovery.replaceChildren();
    announce(ui.error.textContent);
    if (error?.code !== "revision_conflict" || !host.refresh || !recovery)
      return;
    try {
      assertCurrent(context);
      const page = await host.refresh();
      assertCurrent(context);
      if (page.page_id !== context.page_id) throw { code: "action_denied" };
      update(page);
      assertCurrent(context);
      recovery.updated?.(page.rev);
      const save = chrome("button", recovery.saveLabel || "Save my changes");
      save.type = "button";
      save.onclick = (event) => {
        if (!event.isTrusted) return;
        assertCurrent(context);
        recovery.save(page.rev);
      };
      const discard = chrome(
        "button",
        recovery.discardLabel || "Discard my changes",
      );
      discard.type = "button";
      discard.onclick = (event) => {
        if (!event.isTrusted) return;
        assertCurrent(context);
        recovery.discard(page.rev);
        ui.error.hidden = true;
        ui.recovery.replaceChildren();
      };
      ui.recovery.append(save, discard);
    } catch (problem) {
      if (!problem.silent) ui.error.textContent = errorText(problem);
    }
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
      let context;
      try {
        context = capture(w, actionId, record);
        const receipt = await invoke(w, actionId, fixed, event, {
          record,
          context,
        });
        if (receipt) {
          ui.status.textContent = receiptText(receipt);
          announce(ui.status.textContent);
        }
      } catch (error) {
        ui.status.textContent = "";
        await showError(ui, error, undefined, context);
      } finally {
        pending = false;
        button.disabled = !policy(actionId, { widget_id: w.id, record })
          .allowed;
        restoreFocus(button, ui.error.hidden ? ui.status : ui.error, context);
      }
    };
    // Keep schema-invalid buttons unavailable even when host credentials exist.
    if (!button.disabled) {
      const box = element("div", null, "action-feedback");
      // The button is not mounted yet; initialize after its caller appends it.
      queueMicrotask(() => {
        if (!button.isConnected) return;
        button.after(box);
        feedbackBox = box;
        initialize(button, feedback(box), w, actionId, record);
      });
    }
    return button;
  }
  function form(box, w) {
    const p = w.props,
      action = getPage().actions.find((a) => a.id === p.submit_action);
    const node = element("form", null, "page-form");
    node.noValidate = true;
    node.setAttribute("aria-label", action.label);
    const controls = new Map();
    let baseRev = getPage().rev,
      pending = false;
    for (const field of p.fields) {
      const group = element("div", null, "form-field");
      const isRequired =
        field.required || action.input_schema.required?.includes(field.id);
      const label = element("label", field.label);
      if (isRequired) label.append(chrome("span", " (required)"));
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
      if (field.kind === "file" || field.kind === "date") input.lang = "en";
      input.name = field.id;
      input.dataset.focusKey = `field:${field.id}`;
      const required =
        field.required || action.input_schema.required?.includes(field.id);
      input.required = field.kind !== "checkbox" && !!required;
      if (field.kind === "number")
        input.inputMode =
          action.input_schema.properties?.[field.id]?.type === "integer"
            ? "numeric"
            : "decimal";
      if (field.kind === "file") input.accept = field.accept.join(",");
      const initial =
        host.formValues?.(w.id)?.[field.id] ??
        action.input_schema.properties?.[field.id]?.default;
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
      const error = chrome("p", null, "field-error");
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
    const submit = element("button", action.label, "primary-button");
    submit.type = "submit";
    submit.disabled = !policy(action.id, { widget_id: w.id }).allowed;
    node.append(submit);
    const ui = feedback(node);
    box.append(node);
    initialize(submit, ui, w, action.id);
    function draftValues() {
      const values = {};
      for (const [id, { field, input }] of controls) {
        if (field.kind === "file") continue;
        if (field.kind !== "checkbox" && input.value === "") continue;
        values[id] =
          field.kind === "checkbox"
            ? input.checked
            : typedValue(input.value, action.input_schema.properties?.[id]);
      }
      return values;
    }
    const initialValues = draftValues();
    let baseline = {
      ...initialValues,
      ...structuredClone(host.formValues?.(w.id) || {}),
    };
    node.onsubmit = async (event) => {
      event.preventDefault();
      if (pending || !event.isTrusted) return;
      ui.error.hidden = true;
      ui.error.classList.remove("conflict-message");
      submit.hidden = false;
      ui.status.textContent = "";
      ui.recovery.replaceChildren();
      const values = {},
        files = [];
      let invalid;
      for (const { field, input, error } of controls.values()) {
        error.hidden = true;
        error.classList.remove("conflict-message");
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
          const required =
            field.required ||
            getPage()
              .actions.find((a) => a.id === action.id)
              ?.input_schema.required?.includes(field.id);
          if (
            field.kind !== "checkbox" &&
            field.kind !== "select" &&
            input.value === "" &&
            !required
          )
            continue;
          const value =
            field.kind === "checkbox"
              ? input.checked
              : field.kind === "number" || field.kind === "select"
                ? typedValue(input.value, property)
                : input.value;
          message =
            input.value === "" && required && field.kind !== "checkbox"
              ? "Complete this field."
              : fieldError(value, property, required, field.kind);
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
      let context;
      try {
        context = capture(w, action.id, undefined, baseRev);
        const receipt = await invoke(w, action.id, values, event, {
          baseRev,
          files,
          context,
        });
        if (receipt) {
          ui.status.textContent = receiptText(receipt);
          announce(ui.status.textContent);
          baseline = structuredClone(context.submittedInput);
          baseRev = receipt.page_rev ?? getPage()?.rev;
        }
      } catch (error) {
        ui.status.textContent = "";
        await showError(
          ui,
          error,
          {
            updated() {
              ui.error.classList.add("conflict-message");
              submit.hidden = true;
              const hostValues = host.formValues?.(w.id);
              if (!hostValues) return;
              const latest = { ...initialValues, ...hostValues };
              for (const [id, control] of controls) {
                if (
                  JSON.stringify(latest[id]) !== JSON.stringify(baseline[id])
                ) {
                  control.error.hidden = false;
                  control.error.classList.add("conflict-message");
                  const value = element(
                    "bdi",
                    fieldValueText(control.field, latest[id]),
                  );
                  value.lang =
                    control.field.kind === "checkbox"
                      ? "en"
                      : getPage().locale || "en";
                  control.error.replaceChildren(
                    "Changed while you were editing: now ",
                    value,
                  );
                }
              }
            },
            save(revision) {
              baseRev = revision;
              node.requestSubmit(submit);
            },
            discard(revision) {
              baseRev = revision;
              baseline = {
                ...initialValues,
                ...structuredClone(host.formValues?.(w.id) || {}),
              };
              submit.hidden = false;
              ui.error.classList.remove("conflict-message");
              for (const [id, { field, input, error }] of controls) {
                const value =
                  baseline[id] ?? action.input_schema.properties?.[id]?.default;
                if (field.kind === "checkbox") input.checked = value === true;
                else
                  input.value =
                    field.kind === "file" ? "" : String(value ?? "");
                error.hidden = true;
                input.removeAttribute("aria-invalid");
              }
              restoreFocus(submit, ui.status, context);
              announce("Draft discarded.");
            },
          },
          context,
        );
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
        restoreFocus(submit, ui.error.hidden ? ui.status : ui.error, context);
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
    input.lang = "en";
    input.id = `upload-${w.id}`;
    label.htmlFor = input.id;
    input.accept = p.accept.join(",");
    const selected = chrome(
      "p",
      `${fileTypes(p.accept)}, up to ${fileSize(p.max_bytes)}.`,
      "field-description",
    );
    const submit = chrome("button", "Upload");
    submit.type = "submit";
    submit.disabled = !policy(p.action, { widget_id: w.id }).allowed;
    let file,
      pending = false,
      baseRev;
    input.onchange = () => {
      file = input.files[0];
      selectionChanged();
    };
    node.ondragover = (event) => event.preventDefault();
    node.ondrop = (event) => {
      event.preventDefault();
      file = event.dataTransfer.files[0];
      selectionChanged();
    };
    node.append(label, input, selected, submit);
    const ui = feedback(node);
    box.append(node);
    initialize(submit, ui, w, p.action);
    function selectionChanged() {
      const message = acceptableFile(file, p.accept, p.max_bytes);
      ui.error.hidden = !message;
      ui.error.textContent = message || "";
      announce(message || "");
    }
    node.onsubmit = async (event) => {
      event.preventDefault();
      if (pending || !event.isTrusted) return;
      const selectedFile = file;
      ui.status.textContent = "";
      const message = acceptableFile(selectedFile, p.accept, p.max_bytes);
      if (message) {
        ui.error.hidden = false;
        ui.error.textContent = message;
        announce(message);
        return;
      }
      if (!policy(p.action, { widget_id: w.id }).allowed || !host.upload) {
        showError(ui, { code: "action_denied" });
        return;
      }
      pending = true;
      submit.disabled = true;
      submit.hidden = false;
      ui.recovery.replaceChildren();
      ui.error.classList.remove("conflict-message");
      node.setAttribute("aria-busy", "true");
      ui.status.textContent = "Uploading…";
      ui.error.hidden = true;
      let context;
      try {
        context = capture(w, p.action, undefined, baseRev);
        const digest = await fileDigest(selectedFile);
        assertCurrent(context);
        const request = {
          ...requestFor(context, {
            name: selectedFile.name,
            mime: selectedFile.type,
            size: selectedFile.size,
            file_sha256: digest,
          }),
          file: selectedFile,
        };
        const credential = await csrf(context);
        assertCurrent(context);
        const receipt = await host.upload(request, credential);
        assertCurrent(context);
        if (
          !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(
            receipt?.attachment_id || "",
          )
        )
          throw { code: "schema_invalid" };
        ui.status.textContent = `${selectedFile.name} uploaded.`;
        announce(ui.status.textContent);
      } catch (error) {
        ui.status.textContent = "";
        await showError(
          ui,
          error,
          {
            saveLabel: "Retry upload",
            discardLabel: "Discard file",
            updated() {
              submit.hidden = true;
              ui.error.classList.add("conflict-message");
            },
            save(revision) {
              baseRev = revision;
              node.requestSubmit(submit);
            },
            discard(revision) {
              baseRev = revision;
              file = undefined;
              input.value = "";
              submit.hidden = false;
              ui.error.classList.remove("conflict-message");
              restoreFocus(input, ui.status, context);
              announce("File selection discarded.");
            },
          },
          context,
        );
      } finally {
        pending = false;
        node.setAttribute("aria-busy", "false");
        submit.disabled = !policy(p.action, { widget_id: w.id }).allowed;
        restoreFocus(submit, ui.error.hidden ? ui.status : ui.error, context);
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
    capture,
    assertCurrent,
    requestFor,
    policy,
    showError,
    feedback,
  };
}
