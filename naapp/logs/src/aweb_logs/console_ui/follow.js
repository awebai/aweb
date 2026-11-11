// The follow page: polls the server for the events recorded after the last
// position it showed, and appends the server-rendered events to the list.
(() => {
  const follow = document.getElementById("follow");
  if (!follow) return;
  const list = document.getElementById("followed");
  const status = document.getElementById("follow-status");
  const interval = Number(follow.dataset.interval);
  const source = new URL(follow.dataset.source, location.origin);
  let after = follow.dataset.after;
  const waiting = status.textContent;
  let received = 0;

  // The feed's state, live, retrying or stopped, on #follow and in words in
  // the status region; a reconnected feed says again what it has shown.
  const show = (state, words) => {
    follow.dataset.state = state;
    status.textContent = words;
  };
  const live = () =>
    show("live", received > 0 ? `${received} new ${received === 1 ? "event" : "events"}.` : waiting);

  const stop = (id) => {
    show("stopped", "");
    document.getElementById(id).hidden = false;
  };

  // The events of a response, or null when it is not one list of events.
  const eventsOf = (body) => {
    const parsed = new DOMParser().parseFromString(body, "text/html");
    const page = parsed.querySelector("ol[data-after]");
    if (!page) return null;
    const items = Array.from(page.children);
    if (items.some((item) => item.tagName !== "LI")) return null;
    return { after: page.dataset.after, more: "more" in page.dataset, items };
  };

  const poll = async () => {
    source.searchParams.set("after", after);
    let response;
    let body;
    try {
      response = await fetch(source, { credentials: "same-origin" });
      if (response.ok) body = await response.text();
    } catch {
      show("retrying", "Cannot reach the server. Retrying…");
      setTimeout(poll, interval);
      return;
    }
    if (response.status === 401) return stop("follow-ended");
    if (!response.ok) return stop("follow-failed");
    const page = eventsOf(body);
    if (!page) return stop("follow-failed");
    after = page.after;
    for (const item of page.items) {
      list.append(document.adoptNode(item));
      received += 1;
    }
    live();
    setTimeout(poll, page.more ? 0 : interval);
  };

  setTimeout(poll, interval);
})();
