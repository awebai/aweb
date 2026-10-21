// Loopback test host. All snapshots/projections/mutations use the real PageStore.
import { createPageRenderer } from "/assets/page-renderer.js";

async function readJSON(path, body) {
  const response = await fetch(
    path,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return response.json();
}
const host = {
  read: (request) => readJSON("/api/read", request),
  refresh: () => readJSON("/api/page"),
  actionPolicy: () => ({ allowed: true }),
  csrfToken: () => "disposable-loopback-fixture",
};
const renderer = createPageRenderer({
  root: document.querySelector("#page"),
  destinations: document.querySelector("#destinations"),
  announcements: document.querySelector("#announcements"),
  host,
});
renderer.update(await host.refresh());
document.addEventListener("keydown", async (event) => {
  if (event.altKey && event.key === "u") {
    event.preventDefault();
    await readJSON("/api/unrelated-write", {});
    renderer.update(await host.refresh());
  }
});
