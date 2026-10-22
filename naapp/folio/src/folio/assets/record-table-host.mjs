/** Host-owned refusal screen; link secrets and sessions never enter this view. */
export function showRecordTableFailure(root, error) {
  const reopen = error?.code === "link_unavailable";
  const panel = document.createElement("section");
  panel.setAttribute("role", "alert");
  const heading = document.createElement("h1");
  heading.textContent = reopen
    ? "Open the link again"
    : "Unable to open the table";
  heading.tabIndex = -1;
  const help = document.createElement("p");
  help.textContent = reopen
    ? "Open this table again from the dashboard Documents entry or the original link."
    : "The table could not be opened. Try opening it again later.";
  panel.append(heading, help);
  root.replaceChildren(panel);
  heading.focus();
}

/** The shared client owns signing, sessions and secrets; this host owns chrome. */
async function openRecordTable(root, prefix, linkId) {
  let transport, renderer;
  let epoch = 0;
  const identity = document.querySelector("#identity");
  const announcements = document.querySelector("#announcements");
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Refresh table";
  identity.textContent =
    "Live, read-only table. Rows added later appear while the creator has access.";
  identity.append(" ", refresh);

  function clear() {
    ++epoch;
    transport?.clear();
    renderer?.clear();
    refresh.disabled = true;
  }

  function failure(error) {
    if (["client_cleared", "session_changed"].includes(error?.code)) return;
    clear();
    showRecordTableFailure(root, error);
  }

  async function json(path) {
    const started = epoch;
    const response = await transport.request(path);
    const value = await response.json();
    // request() fences its fetch; the host must fence JSON decoding too.
    if (started !== epoch)
      throw Object.assign(Error(), { code: "client_cleared" });
    if (!response.ok) {
      throw Object.assign(Error(), {
        code: value?.detail?.code || "unavailable",
        status: response.status,
      });
    }
    return value;
  }

  try {
    const { createLinkClient } = await import(
      `${prefix}/assets/page-link-client.js`
    );
    // Construct before any app fetch: this immediately captures and scrubs #k.
    transport = createLinkClient({
      linkId,
      sessionPath: `${prefix}/v1/links/${linkId}/session`,
    });
    await transport.connect();
    const { createPageRenderer, createLinkConfirmation } = await import(
      `${prefix}/assets/page-renderer.js`
    );
    const pagePath = `${prefix}/v1/links/${linkId}/page`;
    const adapter = {
      confirmLink: createLinkConfirmation(
        document.querySelector("#link-confirmation"),
      ),
      csrfToken: () => transport.csrfToken(),
      actionPolicy: () => ({ allowed: false }),
      refresh: () => json(pagePath),
      async read({ expected_page_rev, bind }) {
        try {
          return await json(
            `${prefix}/v1/links/${linkId}/query?bind=${encodeURIComponent(JSON.stringify(bind))}&snapshot_rev=${expected_page_rev}`,
          );
        } catch (error) {
          if (error.status === 409) {
            announcements.textContent =
              "Records changed. Refresh the table to restart.";
            error.code = "revision_conflict";
          } else {
            failure(error);
          }
          throw error;
        }
      },
    };
    renderer = createPageRenderer({
      root,
      destinations: document.querySelector("#destinations"),
      announcements,
      host: adapter,
    });
    refresh.onclick = async () => {
      try {
        renderer.update(await json(pagePath));
      } catch (error) {
        failure(error);
      }
    };
    window.addEventListener("pagehide", clear, { once: true });
    renderer.update(await json(pagePath));
  } catch (error) {
    failure(error);
  }
}

const route = location.pathname.match(
  /^(.*)\/present\/links\/(lnk_[a-f0-9]+)$/,
);
const root = document.querySelector("#page");
if (route && root) openRecordTable(root, route[1], route[2]);
