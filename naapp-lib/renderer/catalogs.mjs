// Product chrome is English. page.locale affects only the page container's lang.
export const english = {
  unavailable: "This part of the page can't be shown here.",
  unsupported: "This page can't be shown here",
  unsupportedHelp:
    "It needs a newer version of aweb. Ask the agent that made it to check it.",
  destinations: "Link destinations",
  progress: "Progress",
  busy: "Updating",
  empty: "No records",
  readOnly: "Read only",
  updated: "Updated",
  records: "records",
  previous: "Previous",
  next: "Next",
  actions: "Actions",
  filterField: "Filter field",
  filterValue: "Filter value",
  applyFilter: "Apply filter",
  clearFilter: "Clear filter",
  pagination: "Record pages",
  loading: "Loading records…",
  conflict: "The page changed. Refresh to see the current records.",
  open: "Open",
  cancel: "Cancel",
};
export function messages() {
  return { locale: "en", t: english };
}
