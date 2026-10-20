import { messages } from "./catalogs.mjs";
import { renderMarkdown, safeLink } from "./sanitize.mjs";
import { element } from "./dom.mjs";
import { renderCollection } from "./collections.mjs";
export { createLinkConfirmation } from "./link-host.mjs";
const collectionTypes = new Set([
  "table",
  "cards",
  "list",
  "activity_timeline",
  "chart",
]);
const known = new Set([
  "heading",
  "text",
  "stat",
  "status_badge",
  "stack",
  "grid",
  ...collectionTypes,
]);
const focusables = "a,button,input,select,textarea,[tabindex]";

function setChildren(parent, children) {
  children.forEach((node, index) => {
    if (parent.childNodes[index] !== node)
      parent.insertBefore(node, parent.childNodes[index] || null);
  });
  const keep = new Set(children);
  for (const child of [...parent.childNodes])
    if (!keep.has(child)) child.remove();
}

/** Authorized/validated snapshots only. All authority, host chrome and secrets
 * are supplied by the host, outside root. See docs/page-renderer.md. */
export function createPageRenderer({
  root,
  destinations,
  announcements,
  host = {},
}) {
  if (root.contains(destinations) || root.contains(announcements))
    throw new TypeError("Host chrome must be outside the page");
  let current,
    epoch = 0;
  const cache = new Map(),
    queries = new Map(),
    links = new WeakMap();
  const title = element("h1", null, "page-title");
  function update(page) {
    const before = current;
    current = page;
    const generation =
      before?.page_id !== page?.page_id || before?.rev !== page?.rev
        ? ++epoch
        : epoch;
    const { locale, t } = messages();
    const focused = document.activeElement;
    const focusedWidget = focused?.closest("[data-widget]");
    const focusIndex = focusedWidget
      ? [...focusedWidget.querySelectorAll(focusables)].indexOf(focused)
      : -1;
    const scroll = [scrollX, scrollY];
    if (before?.page_id !== page?.page_id) {
      cache.clear();
      queries.clear();
    } else if (before?.rev !== page?.rev) {
      for (const query of queries.values()) delete query.cursor;
    }
    root.lang = page?.locale || "en";
    destinations.replaceChildren(element("h2", t.destinations));
    destinations.hidden = true;
    if (page?.page_format !== "aweb.page/1" || !Array.isArray(page.layout)) {
      const panel = element("section", null, "page-unavailable");
      panel.setAttribute("role", "alert");
      panel.append(
        element("h1", t.unsupported),
        element("p", t.unsupportedHelp),
      );
      root.replaceChildren(panel);
      cache.clear();
      return;
    }
    title.textContent = page.title;
    const domains = new Set(),
      used = new Set();
    function rememberLink(url) {
      if (!domains.has(url.host)) {
        domains.add(url.host);
        destinations.append(element("bdi", url.host, "destination-domain"));
        destinations.hidden = false;
      }
    }
    function pageLink(node, url) {
      // No native navigation path: middle-click, context menu and modifier
      // gestures cannot bypass host confirmation. URL stays in a WeakMap.
      node.removeAttribute("href");
      node.removeAttribute("target");
      node.removeAttribute("rel");
      node.removeAttribute("referrerpolicy");
      node.setAttribute("role", "link");
      node.tabIndex = 0;
      links.set(node, url.href);
      const activate = (event) => {
        event.preventDefault();
        if (event.isTrusted) host.confirmLink?.(links.get(node), event);
      };
      node.onclick = activate;
      node.onauxclick = (event) => event.preventDefault();
      node.onkeydown = (event) => {
        if (event.key === "Enter" || event.key === " ") activate(event);
      };
      rememberLink(url);
    }
    function displayState(box, w, state) {
      box.setAttribute("aria-busy", String(!!state.busy));
      let status = [...box.children].find((node) =>
        node.hasAttribute("data-widget-state"),
      );
      if (!status) {
        status = element("div", null, "widget-state");
        status.dataset.widgetState = "";
        box.append(status);
      }
      status.replaceChildren();
      const message = state.message || (state.busy ? t.busy : "");
      if (message || state.progress !== undefined)
        status.append(
          element(
            "p",
            `${message}${state.progress !== undefined ? `${message ? " · " : ""}${state.progress}%` : ""}`,
            "state-message",
          ),
        );
      if (state.progress !== undefined) {
        const progress = element("progress");
        progress.max = 100;
        progress.value = state.progress;
        progress.setAttribute(
          "aria-label",
          `${(known.has(w.type) && w.props?.label) || w.id}: ${t.progress}`,
        );
        status.append(progress);
      }
      status.hidden = !status.childNodes.length;
    }
    function widget(w) {
      used.add(w.id);
      const supported = known.has(w.type),
        p = supported ? w.props : {},
        state = page.widget_state?.[w.id] || {};
      const container = w.type === "stack" || w.type === "grid";
      const signature = JSON.stringify([
        !supported
          ? { id: w.id, type: w.type, fallback: w.fallback }
          : container
            ? { ...w, children: undefined }
            : w,
        locale,
        w.bind ? page.rev : undefined,
      ]);
      let entry = cache.get(w.id),
        box;
      if (entry?.signature === signature) {
        box = entry.box;
        if (container)
          setChildren(box, [...w.children.map(widget), entry.state]);
        for (const link of box.querySelectorAll('[role="link"]')) {
          const value = links.get(link);
          if (value) rememberLink(new URL(value));
        }
        displayState(box, w, state);
        return box;
      }
      box = element(
        "section",
        null,
        `widget widget-${supported ? w.type : "unknown"}`,
      );
      box.dataset.widget = w.id;
      if (!supported)
        box.append(
          element("p", t.unavailable, "widget-label"),
          element("p", w.fallback),
        );
      else if (w.type === "heading") box.append(element(`h${p.level}`, p.text));
      else if (w.type === "text") {
        const body = element("div", null, "markdown");
        renderMarkdown(body, p.markdown);
        for (const link of body.querySelectorAll("a[href]")) {
          const url = safeLink(link.getAttribute("href"));
          if (url) pageLink(link, url);
        }
        box.append(body);
      } else if (container) {
        box.classList.add(`gap-${p.gap || "medium"}`);
        if (w.type === "grid") box.classList.add(`columns-${p.columns}`);
        box.append(...w.children.map(widget));
      } else {
        const content = element("div", null, "bound-content");
        box.append(content);
        const actionButton = (id, record) => {
          const button = element(
            "button",
            page.actions.find((a) => a.id === id)?.label || t.actions,
          );
          button.type = "button";
          button.disabled = true;
          button.title = t.readOnly;
          return button;
        };
        const draw = (records, projection) => {
          content.replaceChildren();
          if (collectionTypes.has(w.type)) {
            let query = queries.get(w.id);
            if (!query) {
              query = structuredClone(w.bind);
              queries.set(w.id, query);
            }
            renderCollection({
              box: content,
              w,
              initialRecords: records,
              initialProjection: projection,
              schema: page.collections.find((c) => c.id === w.bind.collection)
                ?.schema,
              locale,
              timeZone: host.timeZone,
              t,
              query,
              actionButton,
              onRead: (bind) => read(bind),
            });
          } else {
            const value = p.field ? records[0]?.value?.[p.field] : p.value;
            if (w.type === "stat" || p.field)
              content.append(element("p", p.label, "widget-label"));
            if (w.type === "stat") {
              const figure = element("div", null, "stat-figure");
              figure.append(
                element(
                  "bdi",
                  typeof value === "number"
                    ? new Intl.NumberFormat(locale).format(value)
                    : (value ?? "—"),
                  "stat-value",
                ),
              );
              if (p.unit) figure.append(element("span", p.unit, "stat-unit"));
              content.append(figure);
            } else
              content.append(
                element(
                  "bdi",
                  p.field ? (value ?? "—") : p.label,
                  `badge tone-${p.tone}`,
                ),
              );
          }
        };
        async function read(bind) {
          if (!host.read) throw Object.assign(Error(), { code: "unavailable" });
          const result = await host.read({
            page_id: page.page_id,
            expected_page_rev: page.rev,
            widget_id: w.id,
            bind,
          });
          if (generation !== epoch || result.page_rev !== page.rev)
            throw Object.assign(Error(), { code: "revision_conflict" });
          return result;
        }
        if (w.bind) {
          content.append(element("p", t.loading));
          read(queries.get(w.id) || w.bind)
            .then((result) => {
              if (generation === epoch) draw(result.records, result);
            })
            .catch((error) => {
              if (generation === epoch)
                content.replaceChildren(
                  element(
                    "p",
                    error.code === "revision_conflict"
                      ? t.conflict
                      : t.unavailable,
                  ),
                );
            });
        } else draw([]);
      }
      displayState(box, w, state);
      entry = {
        signature,
        box,
        state: [...box.children].find((n) =>
          n.hasAttribute("data-widget-state"),
        ),
      };
      cache.set(w.id, entry);
      return box;
    }
    setChildren(root, [title, ...page.layout.map(widget)]);
    for (const id of cache.keys()) if (!used.has(id)) cache.delete(id);
    if (focusedWidget && !focused?.isConnected) {
      const replacement = root
        .querySelector(
          `[data-widget="${CSS.escape(focusedWidget.dataset.widget)}"]`,
        )
        ?.querySelectorAll(focusables)[focusIndex];
      replacement?.focus({ preventScroll: true });
    }
    if (before?.page_id === page.page_id) {
      const changes = [];
      for (const id of new Set([
        ...Object.keys(before.widget_state || {}),
        ...Object.keys(page.widget_state || {}),
      ])) {
        const state = page.widget_state?.[id] || {};
        if (
          JSON.stringify(state) !==
          JSON.stringify(before.widget_state?.[id] || {})
        )
          changes.push(state.message || (state.busy ? t.busy : t.updated));
      }
      if (changes.length) announcements.textContent = changes.join(". ");
      window.scrollTo(...scroll);
    }
  }
  return {
    update,
    clear() {
      host.confirmLink?.clear?.();
      ++epoch;
      current = null;
      cache.clear();
      queries.clear();
      root.replaceChildren();
      destinations.replaceChildren();
      destinations.hidden = true;
      announcements.textContent = "";
    },
    get page() {
      return current;
    },
  };
}
