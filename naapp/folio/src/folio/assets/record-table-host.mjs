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
