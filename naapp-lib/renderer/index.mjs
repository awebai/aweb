import { messages } from "./catalogs.mjs";
import { renderMarkdown, inertLinks } from "./sanitize.mjs";
import { createActions } from "./actions.mjs";
import { createDecision } from "./decisions.mjs";
import { renderMedia, renderPresence } from "./media.mjs";
import { safeLink } from "./sanitize.mjs";
import { element, chrome } from "./dom.mjs";
import { renderCollection } from "./collections.mjs";
export { inertLinks } from "./sanitize.mjs";
export {
  createLinkConfirmation,
  createActionConfirmation,
} from "./link-host.mjs";
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
  "form",
  "decision_card",
  "button",
  "file_drop",
  "image",
  "video",
  "agent_presence",
  "link_out",
  ...collectionTypes,
]);
const focusables = "a,button,input,select,textarea,[tabindex]";

function contentHeading(level, text) {
  const rank = level + 1;
  const heading = element(rank <= 6 ? `h${rank}` : "div", text);
  if (rank > 6) {
    heading.setAttribute("role", "heading");
    heading.setAttribute("aria-level", String(rank));
  }
  return heading;
}

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
  destinations.lang = "en";
  announcements.lang = "en";
  let current,
    epoch = 0;
  const cache = new Map(),
    queries = new Map(),
    decisionAttempts = new Map(),
    links = new WeakMap(),
    domains = new Set();
  const title = element("h1", null, "page-title");
  const actions = createActions({
    host,
    getPage: () => current,
    update,
    announce: (text) => {
      announcements.textContent = text;
    },
  });
  function update(page) {
    const before = current;
    current = page;
    if (before?.page_id !== page?.page_id || before?.rev !== page?.rev) ++epoch;
    const { locale, t } = messages();
    const focused = document.activeElement;
    const focusedWidget = focused?.closest("[data-widget]");
    const focusIndex = focusedWidget
      ? [...focusedWidget.querySelectorAll(focusables)].indexOf(focused)
      : -1;
    const scroll = [scrollX, scrollY];
    if (before?.page_id !== page?.page_id) {
      actions.clear();
      decisionAttempts.clear();
      host.confirmLink?.clear?.();
      host.confirmAction?.clear?.();
      for (const entry of cache.values()) entry.cleanup?.();
      cache.clear();
      queries.clear();
    } else if (before?.rev !== page?.rev) {
      for (const query of queries.values()) delete query.cursor;
    }
    root.lang = page?.locale || "en";
    domains.clear();
    destinations.replaceChildren(element("h2", t.destinations));
    destinations.hidden = true;
    if (page?.page_format !== "aweb.page/1" || !Array.isArray(page.layout)) {
      const panel = chrome("section", null, "page-unavailable");
      panel.setAttribute("role", "alert");
      panel.append(
        element("h1", t.unsupported),
        element("p", t.unsupportedHelp),
      );
      root.replaceChildren(panel);
      for (const entry of cache.values()) entry.cleanup?.();
      actions.clear();
      decisionAttempts.clear();
      host.confirmLink?.clear?.();
      host.confirmAction?.clear?.();
      cache.clear();
      return;
    }
    title.textContent = page.title;
    const used = new Set(),
      decisionWidgets = new Set();
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
      if (w.type === "decision_card") return;
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
      if (message || state.progress !== undefined) {
        const line = state.message
          ? element("p", state.message, "state-message")
          : chrome("p", message, "state-message");
        if (state.progress !== undefined)
          line.append(
            chrome("span", `${message ? " · " : ""}${state.progress}%`),
          );
        status.append(line);
      }
      if (state.progress !== undefined) {
        const progress = element("progress");
        progress.lang = "en";
        progress.max = 100;
        progress.value = state.progress;
        progress.setAttribute("aria-label", t.progress);
        status.append(progress);
      }
      status.hidden = !status.childNodes.length;
    }
    function widget(w) {
      used.add(w.id);
      if (w.type === "decision_card") decisionWidgets.add(w.id);
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
        w.bind
          ? page.collections.find((c) => c.id === w.bind.collection)
              ?.schema_version
          : undefined,
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
        if (
          (w.bind || w.type === "decision_card") &&
          entry.pageRev !== page.rev
        ) {
          entry.pageRev = page.rev;
          entry.refresh?.();
        }
        return box;
      }
      entry?.cleanup?.();
      let refresh, cleanup;
      box = element(
        "section",
        null,
        `widget widget-${supported ? w.type : "unknown"}`,
      );
      box.dataset.widget = w.id;
      if (!supported)
        box.append(
          chrome("p", t.unavailable, "widget-label"),
          element("p", w.fallback),
        );
      else if (w.type === "heading") {
        box.append(contentHeading(p.level, p.text));
      } else if (w.type === "text") {
        const body = element("div", null, "markdown");
        renderMarkdown(body, p.markdown);
        for (const original of body.querySelectorAll("h1,h2,h3,h4,h5,h6")) {
          const heading = contentHeading(Number(original.tagName.slice(1)));
          heading.append(...original.childNodes);
          original.replaceWith(heading);
        }
        for (const { node, url } of inertLinks(body)) pageLink(node, url);
        box.append(body);
      } else if (container) {
        box.classList.add(`gap-${p.gap || "medium"}`);
        if (w.type === "grid") box.classList.add(`columns-${p.columns}`);
        box.append(...w.children.map(widget));
      } else if (w.type === "decision_card") {
        const controller = createDecision({
          box,
          w,
          host,
          actions,
          attempts: decisionAttempts,
          getPage: () => current,
          announce: (text) => {
            announcements.textContent = text;
          },
        });
        refresh = controller.refresh;
        cleanup = controller.clear;
      } else if (w.type === "form") actions.form(box, w);
      else if (w.type === "button")
        box.append(actions.actionButton(w, p.action, null, p.label));
      else if (w.type === "file_drop") actions.fileDrop(box, w);
      else if (w.type === "image" || w.type === "video")
        cleanup = renderMedia(box, w, host);
      else if (w.type === "agent_presence")
        cleanup = renderPresence(box, w, host);
      else if (w.type === "link_out") {
        try {
          const pinned = new URL(host.appOrigin);
          const url = safeLink(new URL(p.path, pinned).href);
          if (
            !url ||
            url.origin !== pinned.origin ||
            pinned.username ||
            pinned.password
          )
            throw Error();
          const link = element("a", p.label);
          pageLink(link, url);
          box.append(link);
        } catch {
          box.append(chrome("p", t.unavailable));
        }
      } else {
        const content = element("div", null, "bound-content");
        box.append(content);
        const actionButton = (id, record) =>
          actions.actionButton(w, id, record);
        let controller;
        const draw = (records, projection) => {
          if (controller) {
            controller.updateProjection(projection);
            return;
          }
          content.replaceChildren();
          if (collectionTypes.has(w.type)) {
            let query = queries.get(w.id);
            if (!query) {
              query = structuredClone(w.bind);
              queries.set(w.id, query);
            }
            controller = renderCollection({
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
              pageLink,
              onRead: (bind) => read(bind),
              announce: (text) => {
                announcements.textContent = text;
              },
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
              if (value === undefined || value === null) {
                figure.setAttribute("role", "img");
                figure.setAttribute("aria-label", "No value");
                figure.lang = "en";
              }
              if (typeof value === "number") figure.firstChild.lang = "en";
              if (p.unit && value !== undefined && value !== null)
                figure.append(element("span", p.unit, "stat-unit"));
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
          const snapshot = current,
            requestEpoch = epoch;
          const result = await host.read({
            page_id: snapshot.page_id,
            expected_page_rev: snapshot.rev,
            widget_id: w.id,
            bind,
          });
          if (requestEpoch !== epoch || result.page_rev !== snapshot.rev)
            throw Object.assign(Error(), { code: "revision_conflict" });
          return result;
        }
        if (w.bind) {
          let serial = 0;
          refresh = async () => {
            const request = ++serial;
            if (controller) controller.beginRefresh();
            else content.replaceChildren(chrome("p", t.loading));
            try {
              const result = await read(queries.get(w.id) || w.bind);
              if (request === serial && box.isConnected)
                draw(result.records, result);
            } catch (error) {
              if (request !== serial || !box.isConnected) return;
              const message =
                error.code === "revision_conflict" ? t.conflict : t.unavailable;
              if (controller) controller.showError(message);
              else content.replaceChildren(chrome("p", message));
            }
          };
          refresh();
        } else draw([]);
      }
      displayState(box, w, state);
      entry = {
        signature,
        box,
        refresh,
        cleanup,
        pageRev: page.rev,
        state: [...box.children].find((n) =>
          n.hasAttribute("data-widget-state"),
        ),
      };
      cache.set(w.id, entry);
      return box;
    }
    setChildren(root, [title, ...page.layout.map(widget)]);
    for (const id of cache.keys())
      if (!used.has(id)) {
        cache.get(id).cleanup?.();
        cache.delete(id);
      }
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
        if (decisionWidgets.has(id)) continue;
        const state = page.widget_state?.[id] || {};
        if (
          JSON.stringify(state) !==
          JSON.stringify(before.widget_state?.[id] || {})
        ) {
          const message = state.message
            ? element("span", state.message)
            : chrome("span", state.busy ? t.busy : t.updated);
          if (state.message) message.lang = page.locale || "en";
          changes.push(message);
        }
      }
      if (changes.length)
        announcements.replaceChildren(
          ...changes.flatMap((node, i) => (i ? [". ", node] : [node])),
        );
      window.scrollTo(...scroll);
    }
  }
  return {
    update,
    clear() {
      host.confirmLink?.clear?.();
      host.confirmAction?.clear?.();
      actions.clear();
      decisionAttempts.clear();
      for (const entry of cache.values()) entry.cleanup?.();
      ++epoch;
      current = null;
      cache.clear();
      queries.clear();
      domains.clear();
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
