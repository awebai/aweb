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
  let received = 0;

  const stop = (id) => {
    status.textContent = "";
    document.getElementById(id).hidden = false;
  };

  const poll = async () => {
    source.searchParams.set("after", after);
    let response;
    try {
      response = await fetch(source, { credentials: "same-origin" });
    } catch {
      setTimeout(poll, interval);
      return;
    }
    if (response.status === 401) return stop("follow-ended");
    if (!response.ok) return stop("follow-failed");
    const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
    const page = parsed.querySelector("ol[data-after]");
    if (!page) return stop("follow-failed");
    after = page.dataset.after;
    for (const item of Array.from(page.children)) {
      list.append(document.adoptNode(item));
      received += 1;
    }
    if (received > 0) status.textContent = `${received} new ${received === 1 ? "event" : "events"}.`;
    setTimeout(poll, page.dataset.more ? 0 : interval);
  };

  setTimeout(poll, interval);
})();
