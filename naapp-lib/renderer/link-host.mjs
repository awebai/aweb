import { element } from "./dom.mjs";
import { safeLink } from "./sanitize.mjs";
import { messages } from "./catalogs.mjs";

/** The host creates this native dialog outside the page container. No page
 * attributes or markup supply URLs or controls. Only trusted gestures open it. */
export function createLinkConfirmation(dialog) {
  const { t } = messages();
  dialog.setAttribute("aria-labelledby", "link-destination-title");
  const confirm = (destination, event) => {
    if (!event?.isTrusted || !navigator.userActivation.isActive) return;
    const url = safeLink(destination);
    if (!url || dialog.open) return;
    const trigger = document.activeElement;
    const title = element("h2", url.host, "destination-title");
    title.id = "link-destination-title";
    const address = element("p", url.href, "destination-url");
    const open = element("button", `${t.open} ${url.host}`);
    open.type = "button";
    const cancel = element("button", t.cancel);
    cancel.type = "button";
    cancel.autofocus = true;
    open.onclick = () => {
      window.open(url.href, "_blank", "noopener,noreferrer");
      dialog.close();
    };
    cancel.onclick = () => dialog.close();
    dialog.onclose = () => {
      if (trigger?.isConnected) trigger.focus({ preventScroll: true });
    };
    dialog.replaceChildren(title, address, open, cancel);
    dialog.showModal();
    cancel.focus();
  };
  confirm.clear = () => {
    dialog.close();
    dialog.replaceChildren();
  };
  return confirm;
}

export function createActionConfirmation(dialog) {
  dialog.setAttribute("aria-labelledby", "action-confirmation-title");
  let settle;
  const confirm = (details, event) => {
    if (!event?.isTrusted || !navigator.userActivation.isActive || dialog.open)
      return Promise.resolve(false);
    return new Promise((resolve) => {
      settle = resolve;
      const title = element("h2", details.description || details.label);
      title.id = "action-confirmation-title";
      const yes = element("button", details.label);
      yes.type = "button";
      const cancel = element("button", "Cancel");
      cancel.type = "button";
      cancel.autofocus = true;
      let accepted = false;
      const trigger = document.activeElement;
      yes.onclick = () => {
        accepted = true;
        dialog.close();
      };
      cancel.onclick = () => dialog.close();
      dialog.onclose = () => {
        settle?.(accepted);
        settle = null;
        if (trigger?.isConnected) trigger.focus({ preventScroll: true });
      };
      dialog.replaceChildren(title, yes, cancel);
      dialog.showModal();
      cancel.focus();
    });
  };
  confirm.clear = () => {
    settle?.(false);
    settle = null;
    dialog.close();
    dialog.replaceChildren();
  };
  return confirm;
}
