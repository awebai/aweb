import { element, chrome } from "./dom.mjs";
import { messages } from "./catalogs.mjs";
import { renderCollection } from "./collections.mjs";
import { createRowDraft } from "./row-draft.mjs";
import { typedValue } from "./input.mjs";

const button = (label, click) => {
  const node = chrome("button", label);
  node.type = "button";
  node.onclick = click;
  return node;
};

// Checked host data supplies all authority. Prose saves and row saves are separate.
export function mountTableWidget({ root, widgetId, state, host = {} }) {
  let active = true,
    writing = false,
    conflicted = false,
    draft,
    operation,
    controls = [],
    controller;
  let projection = state.query;
  let currentCursor;
  const { locale, t } = messages();
  root.replaceChildren();
  root.classList.add("widget");
  const status = chrome("p", "", "row-status");
  status.setAttribute("role", "status");
  const formRoot = element("div", null, "row-editor");
  const conflictRoot = element("div", null, "row-conflict");
  const tableRoot = element("div");
  const commands = element("div", null, "row-commands");
  root.append(commands, tableRoot, formRoot, conflictRoot, status);
  if (state.state !== "ready") {
    status.textContent =
      state.state === "records_identity_required"
        ? state.reopen === "new_link_from_sharer"
          ? "This table needs a new link from the person who shared this document."
          : "Reopen Edit from your dashboard to use this table."
        : "This table is unavailable. Your text is still here.";
    return {
      get dirty() {
        return false;
      },
      clear() {
        active = false;
        root.replaceChildren();
      },
    };
  }
  const page = state.page;
  const widget = page.layout.find(
    (w) => w.id === widgetId && w.type === "table",
  );
  const collection = page.collections.find(
    (c) => c.id === widget?.bind.collection,
  );
  if (!widget || !collection || !projection)
    throw new TypeError("Invalid checked table state");
  const schema = collection.schema;
  const capabilities = state.edit || {};
  const patchFields = (capabilities.patch_fields || []).filter((field) =>
    Object.hasOwn(schema.properties || {}, field),
  );
  commands.append(
    chrome(
      "p",
      state.data_mode === "pinned"
        ? "Saved table rows"
        : "Table rows are current, even when this document is an older version.",
      "field-description",
    ),
  );
  if (capabilities.reopen_to_edit) {
    const reopen = chrome(
      "p",
      "Reopen Edit from your dashboard to edit this table.",
    );
    reopen.dataset.reopenToEdit = "";
    commands.append(reopen);
  }
  const add =
    capabilities.add && typeof host.add === "function"
      ? button("Add row", () => begin("add"))
      : null;
  if (add) commands.append(add);
  commands.append(button("Refresh rows", () => refresh()));
  function notify() {
    host.onDraftChange?.(!!draft);
  }
  function sync() {
    for (const input of controls)
      input.disabled = writing || !!draft?.pending || conflicted;
    formRoot
      .querySelectorAll("button")
      .forEach((node) => (node.disabled = writing || conflicted));
    const cancel = formRoot.querySelector("[data-cancel-row]");
    if (cancel) cancel.disabled = writing || !!draft?.pending;
    if (add) add.disabled = !!draft || writing;
    tableRoot
      .querySelectorAll("[data-row-command]")
      .forEach((node) => (node.disabled = !!draft || writing));
  }
  async function read(cursor) {
    const result = await host.query({ cursor });
    if (!active) throw { code: "unavailable" };
    projection = result;
    currentCursor = cursor;
    return result;
  }
  async function refresh() {
    try {
      const result = await read();
      if (active) {
        controller.beginRefresh();
        controller.updateProjection(result);
        sync();
      }
    } catch {
      if (active) {
        controller.showError(
          "Rows could not be refreshed. Your draft is kept.",
        );
        status.textContent = "Rows could not be refreshed. Try again.";
      }
    }
  }
  function end(message) {
    draft = undefined;
    operation = undefined;
    conflicted = false;
    formRoot.replaceChildren();
    conflictRoot.replaceChildren();
    controls = [];
    status.textContent = message;
    notify();
    sync();
  }
  function fieldInput(field) {
    const fieldSchema = schema.properties[field];
    const types = Array.isArray(fieldSchema.type)
      ? fieldSchema.type
      : [fieldSchema.type];
    const label = element("label", null, "row-field");
    label.append(
      element(
        "span",
        fieldSchema.title ||
          widget.props.columns.find((c) => c.field === field)?.label ||
          field,
      ),
    );
    const value = draft.values[field];
    let input, getValue;
    const choices =
      fieldSchema.enum ||
      (types.includes("boolean")
        ? [true, false, ...(types.includes("null") ? [null] : [])]
        : null);
    if (choices) {
      input = element("select");
      const empty = element("option", "Choose a value");
      empty.value = "";
      input.append(empty);
      choices.forEach((choice, i) => {
        const option = element(
          "option",
          choice === null ? "Empty" : String(choice),
        );
        option.value = String(i);
        input.append(option);
      });
      const selected = choices.findIndex((choice) => choice === value);
      input.value = selected < 0 ? "" : String(selected);
      getValue = () =>
        input.value === "" ? undefined : choices[Number(input.value)];
    } else {
      const complex =
        types.includes("object") ||
        types.includes("array") ||
        types.includes("null");
      input = element(complex ? "textarea" : "input");
      if (!complex) {
        input.type = "text";
        if (types.includes("integer")) input.inputMode = "numeric";
      }
      input.value =
        value === undefined
          ? ""
          : complex
            ? JSON.stringify(value)
            : String(value);
      getValue = () => {
        if (!complex) return typedValue(input.value, fieldSchema);
        try {
          return JSON.parse(input.value);
        } catch {
          return undefined;
        }
      };
    }
    input.oninput = () => {
      draft.set(field, getValue());
      input.removeAttribute("aria-invalid");
      status.textContent =
        "Row draft — save this row separately from your text.";
      notify();
    };
    controls.push(input);
    label.append(input);
    return label;
  }
  function drawForm() {
    controls = [];
    formRoot.replaceChildren();
    if (operation !== "delete") {
      const fields =
        operation === "add"
          ? Object.keys(schema.properties || {})
          : patchFields;
      formRoot.append(
        chrome(
          "h3",
          operation === "add" ? "New row" : "Edit row " + draft.record.id,
        ),
      );
      for (const field of fields) formRoot.append(fieldInput(field));
    }
    formRoot.append(
      button(operation === "delete" ? "Retry deletion" : "Save row", () =>
        submit(),
      ),
    );
    const cancel = button("Discard row draft", () =>
      end("Row draft discarded. Saved rows and your text are unchanged."),
    );
    cancel.dataset.cancelRow = "";
    formRoot.append(cancel);
    sync();
  }
  function begin(kind, record) {
    if (!active || draft) return false;
    operation = kind;
    draft = createRowDraft({
      operation,
      record,
      fields:
        kind === "update" ? patchFields : Object.keys(schema.properties || {}),
      schema,
    });
    conflicted = false;
    conflictRoot.replaceChildren();
    drawForm();
    notify();
    sync();
    controls[0]?.focus();
    return true;
  }
  async function conflict() {
    conflicted = true;
    sync();
    conflictRoot.replaceChildren(
      chrome(
        "p",
        "This row changed. Your input is kept. Loading the current row…",
      ),
    );
    let current;
    try {
      current = (await read(currentCursor)).records.find(
        (record) => record.id === draft.record.id,
      );
    } catch {
      /* keep draft */
    }
    if (!active || !draft) return;
    conflictRoot.replaceChildren(
      chrome(
        "p",
        current
          ? "This row changed. Compare the current row with your input before saving again."
          : "The current row is not available in this table. Your input is kept; discard the row draft or copy it before reopening Edit.",
      ),
    );
    if (current) {
      conflictRoot.append(
        element("pre", JSON.stringify(current.value, null, 2)),
      );
      conflictRoot.append(
        button(
          operation === "delete"
            ? "Use current row revision"
            : "Keep my changes",
          () => {
            draft.rebase(current);
            conflicted = false;
            conflictRoot.replaceChildren();
            drawForm();
            status.textContent =
              "Current revision loaded. Review your draft, then save the row.";
          },
        ),
      );
    }
    conflictRoot.append(
      button("Discard row draft", () => end("Row draft discarded.")),
    );
  }
  async function submit() {
    if (!active || !draft || writing || conflicted) return;
    let request;
    try {
      request = draft.request();
    } catch (error) {
      status.textContent =
        error.code === "no_changes"
          ? "No row changes to save."
          : "Check the row fields. Your input has been kept.";
      controls.forEach((input) => input.setAttribute("aria-invalid", "true"));
      return;
    }
    writing = true;
    sync();
    status.textContent = "Saving row…";
    try {
      await host[operation === "update" ? "patch" : operation](request);
      if (!active) return;
      writing = false;
      end("Row saved. Your text is saved separately.");
      await refresh();
    } catch (error) {
      if (!active) return;
      writing = false;
      if (error?.code === "revision_conflict" && error?.status === 409) {
        draft.settle();
        await conflict();
      } else if ([400, 422].includes(error?.status)) {
        draft.settle();
        status.textContent =
          "This row was refused. Check its values; your input is kept.";
      } else {
        // Even a failed response can follow a committed write. Retain key and bytes.
        status.textContent =
          "The row save could not be confirmed. Retry to check the same save; your input is kept.";
      }
      sync();
    }
  }
  controller = renderCollection({
    box: tableRoot,
    w: widget,
    initialRecords: collection.records || [],
    initialProjection: projection,
    schema,
    locale,
    timeZone: page.time_zone,
    t,
    query: structuredClone(widget.bind),
    sortEnabled: false,
    onRead: (bind) => read(bind.cursor),
    announce: (message) => (status.textContent = message),
    pageLink(node, url) {
      node.setAttribute("role", "link");
      node.tabIndex = 0;
      const activate = (event) => {
        event.preventDefault();
        if (active && event.isTrusted) host.confirmLink?.(url.href, event);
      };
      node.onclick = activate;
      node.onauxclick = (event) => event.preventDefault();
      node.onkeydown = (event) => {
        if (["Enter", " "].includes(event.key)) activate(event);
      };
    },
    rowControls:
      (patchFields.length && typeof host.patch === "function") ||
      (capabilities.delete && typeof host.delete === "function")
        ? (record) => {
            const group = element("div", null, "row-commands");
            if (patchFields.length && typeof host.patch === "function") {
              const edit = button("Edit row " + record.id, () =>
                begin("update", record),
              );
              edit.disabled = !!draft || writing;
              edit.dataset.rowCommand = "";
              group.append(edit);
            }
            if (capabilities.delete && typeof host.delete === "function") {
              const remove = button(
                "Delete row " + record.id,
                async (event) => {
                  if (!active || draft || writing || !event.isTrusted) return;
                  const accepted = await host.confirmDelete?.(record, event);
                  if (!active || draft || !accepted) return;
                  if (begin("delete", record)) await submit();
                },
              );
              remove.disabled = !!draft || writing;
              remove.dataset.rowCommand = "";
              group.append(remove);
            }
            return group;
          }
        : undefined,
  });
  return {
    get dirty() {
      return !!draft;
    },
    refresh,
    clear() {
      active = false;
      controller.clear();
      root.replaceChildren();
    },
  };
}
