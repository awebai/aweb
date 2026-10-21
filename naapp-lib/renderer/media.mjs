import { element, chrome } from "./dom.mjs";

export function renderMedia(box, w, host) {
  const p = w.props,
    figure = element("figure");
  box.append(figure);
  const message = chrome("p", "Loading media…", "field-description");
  figure.append(message);
  const unavailable = () => {
    const alt = element("span", p.alt);
    alt.lang = box.closest("[lang]")?.lang || "en";
    message.replaceChildren("Media unavailable. ", alt);
    message.hidden = false;
  };
  let disposed = false;
  Promise.resolve()
    .then(() => host.asset?.(p.asset_id))
    .then((reference) => {
      if (disposed) return;
      const origin = new URL(host.assetOrigin),
        url = new URL(
          typeof reference === "string" ? reference : reference?.url,
        );
      if (
        origin.protocol !== "https:" ||
        origin.username ||
        origin.password ||
        origin.origin === location.origin ||
        origin.pathname !== "/" ||
        origin.search ||
        origin.hash ||
        url.origin !== origin.origin ||
        url.username ||
        url.password
      )
        throw Error("asset_origin");
      const media = element(w.type === "image" ? "img" : "video");
      media.referrerPolicy = "no-referrer";
      media.src = url.href;
      if (w.type === "image") {
        media.alt = p.alt;
        media.loading = "lazy";
        media.decoding = "async";
      } else {
        media.controls = true;
        media.preload = "metadata";
        media.setAttribute("aria-label", p.alt);
        media.append(element("p", p.alt));
      }
      media.onerror = () => {
        unavailable();
      };
      media.onload = () => {
        message.hidden = true;
      };
      media.onloadedmetadata = () => {
        message.hidden = true;
      };
      message.hidden = true;
      figure.append(media);
      if (p.caption) figure.append(element("figcaption", p.caption));
    })
    .catch(() => {
      if (!disposed) unavailable();
    });
  return () => {
    disposed = true;
    for (const video of figure.querySelectorAll("video")) {
      video.pause();
      video.removeAttribute("src");
      video.load();
    }
  };
}

export function renderPresence(box, w, host) {
  const subject = element("p", w.props.subject, "widget-label"),
    status = chrome("p", "Unknown"),
    age = chrome("p", null, "field-description");
  box.append(subject, status, age);
  let disposed = false,
    timer;
  Promise.resolve()
    .then(() => host.health?.(w.props.subject))
    .then((evidence) => {
      if (disposed) return;
      function display() {
        const observed = Date.parse(evidence?.observed_at),
          until = Date.parse(evidence?.valid_until),
          now = Date.now();
        const valid =
          evidence?.subject === w.props.subject &&
          Number.isFinite(observed) &&
          Number.isFinite(until) &&
          observed <= now + 30000 &&
          observed < until &&
          until - observed <= 900000 &&
          until > now;
        if (!valid) {
          status.textContent = "Unknown";
          age.textContent = Number.isFinite(observed)
            ? `Reported ${new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: host.timeZone }).format(observed)}`
            : "No current host report";
          return;
        }
        const states = {
          yes: "Ready",
          degraded: "Unknown",
          no: "Offline",
          unknown: "Unknown",
        };
        status.textContent = states[evidence.reachable] || states.unknown;
        for (const text of [
          evidence.reason?.text && ` · ${evidence.reason.text}`,
          evidence.fixing?.text && ` ${evidence.fixing.text}`,
        ]) {
          if (!text) continue;
          const report = element("span", text);
          report.lang = box.closest("[lang]")?.lang || "en";
          status.append(report);
        }
        const seconds = Math.max(0, Math.floor((now - observed) / 1000));
        age.textContent = `Reported ${seconds < 60 ? "less than a minute ago" : `${Math.floor(seconds / 60)} minutes ago`}`;
      }
      display();
      timer = setInterval(display, 1000);
    })
    .catch(() => {
      if (!disposed) age.textContent = "No current host report";
    });
  return () => {
    disposed = true;
    clearInterval(timer);
  };
}
