import {
  mountTableWidget,
  createLinkConfirmation,
  createActionConfirmation,
} from "/present/widgets/assets/renderer.js";

// The caller supplies a checked route prefix and session fetch closure. No
// widget definition can select an endpoint, identity, collection or operation.
export function createWidgetHost({
  fetcher,
  prefix,
  editable = false,
  onDraftChange = () => {},
}) {
  const entries = new Map();
  const linkDialog = document.createElement("dialog");
  const actionDialog = document.createElement("dialog");
  linkDialog.className = actionDialog.className = "link-confirmation";
  document.body.append(linkDialog, actionDialog);
  const confirmLink = createLinkConfirmation(linkDialog);
  const confirmAction = createActionConfirmation(actionDialog);
  let active = true;
  async function request(widgetId, suffix = "", payload, cursor) {
    if (!active) throw { code: "unavailable", status: 404 };
    const path =
      prefix + "/widgets/" + encodeURIComponent(widgetId) + "/records" + suffix;
    const response = await fetcher(
      path + (cursor ? "?cursor=" + encodeURIComponent(cursor) : ""),
      {
        ...(payload
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(payload),
            }
          : {}),
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      },
    );
    let body;
    try {
      body = await response.json();
    } catch {
      throw { code: "unknown_outcome", status: response.status };
    }
    if (!active) throw { code: "unavailable", status: 404 };
    if (!response.ok)
      throw {
        code: body.detail?.code || body.code || "unavailable",
        status: response.status,
      };
    return body;
  }
  function install(id, root, state) {
    const old = entries.get(id);
    // Keep the actual mounted form/draft through preview and prose redraws.
    if (old && old.signature === JSON.stringify(state)) {
      root.replaceWith(old.root);
      return old.root;
    }
    if (old?.controller.dirty) {
      root.replaceWith(old.root);
      old.pendingState = state;
      return old.root;
    }
    old?.controller.clear();
    const entry = { root, signature: JSON.stringify(state) };
    entry.controller = mountTableWidget({
      root,
      widgetId: id,
      state: editable ? state : { ...state, edit: {} },
      host: {
        query: ({ cursor }) => request(id, "", undefined, cursor),
        ...(editable
          ? {
              add: (payload) => request(id, "/add", payload),
              patch: (payload) => request(id, "/update", payload),
              delete: (payload) => request(id, "/delete", payload),
              confirmDelete: (record, event) =>
                confirmAction(
                  {
                    label: "Delete row",
                    description: "Delete row " + record.id + "?",
                  },
                  event,
                ),
            }
          : {}),
        confirmLink,
        onDraftChange(dirty) {
          onDraftChange(dirty);
          // Apply refreshed capabilities only after the draft ends, never by
          // destroying input while another text version arrives.
          if (!dirty && entry.pendingState) {
            const next = entry.pendingState;
            entry.pendingState = undefined;
            queueMicrotask(() => {
              if (active && !entry.controller.dirty)
                install(id, entry.root, next);
            });
          }
        },
      },
    });
    entries.set(id, entry);
    return root;
  }
  return {
    mount(id, root, state = { state: "unavailable" }) {
      return install(id, root, state);
    },
    get dirty() {
      return [...entries.values()].some((entry) => entry.controller.dirty);
    },
    prune(ids) {
      for (const [id, entry] of entries)
        if (!ids.has(id) && !entry.controller.dirty) {
          entry.controller.clear();
          entries.delete(id);
        }
    },
    clear() {
      active = false;
      for (const entry of entries.values()) entry.controller.clear();
      entries.clear();
      confirmAction.clear();
      confirmLink.clear();
      linkDialog.remove();
      actionDialog.remove();
    },
  };
}

export async function mountReadonlyWidgets({ root, token }) {
  const prefix = "/present/" + encodeURIComponent(token);
  const fetcher = (path, options) => fetch(path, options);
  const host = createWidgetHost({ fetcher, prefix });
  try {
    const response = await fetcher(prefix + "/widgets", {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error("unavailable");
    const state = await response.json();
    for (const node of root.querySelectorAll("[data-folio-widget]"))
      host.mount(
        node.dataset.folioWidget,
        node,
        state.widgets?.[node.dataset.folioWidget],
      );
  } catch {
    for (const node of root.querySelectorAll("[data-folio-widget]"))
      host.mount(node.dataset.folioWidget, node);
  }
  return host;
}

// Only server-authored script nodes survive the document sanitizer. Each host
// module URL is fixed and admitted by that response's nonce.
for (const script of document.querySelectorAll("script[data-folio-readonly]")) {
  const root = document.querySelector(".document-body");
  if (root && script.dataset.widgetToken)
    mountReadonlyWidgets({ root, token: script.dataset.widgetToken });
}
