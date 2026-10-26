import { createDocumentModel } from "./document-model.mjs";
import { createWidgetHost } from "./folio-widget-host.mjs";

export function createAtomicEditor({
  container,
  bodyInput,
  fetcher,
  onDraftChange,
}) {
  let model,
    savedSegments,
    savedProse,
    currentWidgets = {};
  const region = document.createElement("div");
  region.className = "atomic-document";
  container.append(region);
  const host = createWidgetHost({
    fetcher,
    prefix: "",
    editable: true,
    onDraftChange,
  });
  const previewHost = createWidgetHost({ fetcher, prefix: "" });
  let inputs = [];
  function show(segments, widgets) {
    model = createDocumentModel(segments);
    savedSegments = structuredClone(segments);
    savedProse = model.prose;
    currentWidgets = widgets;
    const ids = new Set();
    const nodes = [];
    inputs = [];
    for (const part of model.parts) {
      if (part.kind === "prose") {
        const label = document.createElement("label");
        label.className = "atomic-prose";
        const heading = document.createElement("span");
        heading.className = "sr-only";
        heading.textContent = "Document text " + (part.index + 1);
        const input = document.createElement("textarea");
        input.className = "editor";
        input.setAttribute("aria-label", heading.textContent);
        input.spellcheck = false;
        input.value = part.text;
        // Avoid HTML textarea CRLF normalization changing untouched segments.
        input.oninput = () => {
          model.setProse(part.index, input.value);
          bodyInput.value = model.serialize();
          bodyInput.dispatchEvent(new Event("input", { bubbles: true }));
        };
        label.append(heading, input);
        inputs.push(input);
        nodes.push(label);
      } else {
        ids.add(part.id);
        const block = document.createElement("section");
        block.className = "folio-widget";
        block.dataset.folioWidget = part.id;
        block.setAttribute("aria-label", "Table " + part.id);
        // Never put part.raw or JSON in the DOM or editable field.
        nodes.push(host.mount(part.id, block, widgets[part.id]));
      }
    }
    region.replaceChildren(...nodes);
    host.prune(ids);
    bodyInput.value = model.serialize();
    bodyInput.hidden = true;
    region.hidden = false;
  }
  return {
    update(state) {
      show(state.segments, state.widgets || {});
    },
    serialize() {
      return model.serialize();
    },
    captureProse() {
      return model.prose;
    },
    markSaved(prose) {
      savedProse = [...prose];
    },
    resetProse() {
      model.restoreProse(savedProse);
      const parts = model.parts;
      const segments = savedSegments.map((part, index) =>
        part.kind === "prose" ? { ...part, text: parts[index].text } : part,
      );
      show(segments, currentWidgets);
    },
    mountPreview(root) {
      const ids = new Set();
      for (const node of root.querySelectorAll("[data-folio-widget]")) {
        const id = node.dataset.folioWidget;
        ids.add(id);
        previewHost.mount(id, node, currentWidgets[id]);
      }
      previewHost.prune(ids);
    },
    get rowDirty() {
      return host.dirty;
    },
    get proseText() {
      return model.parts
        .filter((part) => part.kind === "prose")
        .map((part) => part.text)
        .join("\n\n");
    },
    focus() {
      inputs[0]?.focus();
    },
    selectProse() {
      inputs[0]?.focus();
      inputs[0]?.select();
    },
    clear() {
      host.clear();
      previewHost.clear();
      region.remove();
      bodyInput.hidden = false;
    },
  };
}
