import {
  createPageRenderer,
  createLinkConfirmation,
  createActionConfirmation,
} from "/assets/page-renderer.js";
const query = new URLSearchParams(location.search);
let configuration = await fetch("/api/host?" + query).then((r) => r.json());
async function send(path, request, credential) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": credential.csrfToken,
    },
    body: JSON.stringify(request),
  });
  const body = await response.json();
  if (!response.ok) throw body;
  return body;
}
const readPage = async () => {
  configuration = await fetch("/api/host?" + query).then((r) => r.json());
  return fetch("/api/page?" + query).then((r) => r.json());
};
const host = {
  confirmLink: createLinkConfirmation(
    document.querySelector("#link-confirmation"),
  ),
  confirmAction: createActionConfirmation(
    document.querySelector("#action-confirmation"),
  ),
  csrfToken: () => configuration.csrf_token,
  formValues: (widget) => configuration.form_values[widget],
  actionPolicy: (action) => ({
    allowed: configuration.allowed_actions.includes(action),
    consequential: action === "request-visit",
  }),
  invoke: (request, credential) => send("/api/invoke", request, credential),
  answer: (request, credential) => send("/api/answer?" + query, request, credential),
  decision: async (task_id) => {
    const params = new URLSearchParams(query);
    params.set("task_id", task_id);
    const response = await fetch("/api/decision?" + params);
    const body = await response.json();
    if (!response.ok) throw body;
    return body;
  },
  upload: async (request, credential) => {
    const { file, ...context } = request;
    const bytes = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result.split(",")[1]);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
    return send(
      "/api/upload",
      {
        ...context,
        file: { name: file.name, mime: file.type, size: file.size, bytes },
      },
      credential,
    );
  },
  assetOrigin: configuration.asset_origin,
  appOrigin: configuration.app_origin,
  asset: (asset_id) =>
    (query.get("case") === "wrong-asset"
      ? "https://forbidden.example"
      : configuration.asset_origin) +
    "/" +
    (asset_id === "property-tour" ? "property-tour" : "property-illustration"),
  health: async () => configuration.health,
  refresh: readPage,
  read: async (request) => {
    const params = new URLSearchParams(query);
    params.set("bind", JSON.stringify(request.bind));
    params.set("expected_page_rev", String(request.expected_page_rev));
    const response = await fetch("/api/widget?" + params);
    const body = await response.json();
    if (!response.ok) throw body;
    return body;
  },
};
const renderer = createPageRenderer({
  root: document.querySelector("#page"),
  destinations: document.querySelector("#destinations"),
  announcements: document.querySelector("#announcements"),
  host,
});
async function refresh() {
  renderer.update(await readPage());
}
document.querySelector("#identity").textContent = "Fixture gallery";
document.addEventListener("keydown", async (event) => {
  if (event.altKey && ["u", "c", "f"].includes(event.key)) {
    event.preventDefault();
    await send(
      "/api/fixture-change",
      {
        mode:
          event.key === "u" ? "state" : event.key === "f" ? "form" : "record",
      },
      { csrfToken: configuration.csrf_token },
    );
    if (event.key === "u") await refresh();
  }
});
await refresh();
