// The words a person sees for one frozen request, filled from the operation
// definition's display. operation_display.py fills the same templates the
// same way for mail, the owner page and the CLI, so every surface says the same.
import { canonical } from "./canonical-json.mjs";

const refused = () => { throw new Error("handoff_refused"); };
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);

function read(request, pointer) {
  let value = request;
  for (const part of pointer.split("/").slice(1)) {
    if (!object(value) || !Object.hasOwn(value, part)) refused();
    value = value[part];
  }
  return value;
}

function words(value) {
  if (typeof value === "string") return value;
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value) && value.every(item => typeof item === "string")) return value.join(", ");
  refused();
}

function technical(value) {
  if (typeof value === "string" || Number.isSafeInteger(value) ||
      (Array.isArray(value) && value.every(item => typeof item === "string"))) return words(value);
  return canonical(value);
}

function label(key) {
  const text = key.replaceAll("_", " ");
  return text.slice(0, 1).toUpperCase() + text.slice(1);
}

const fill = (template, request) =>
  template.replace(/\{(\/[^{}]*)\}/g, (_, pointer) => words(read(request, pointer)));

export function renderDisplay(display, request) {
  return {
    title: fill(display.title, request),
    consequences: display.consequences.map(line => fill(line, request)),
    names: Object.entries(display.names).map(([key, source]) => [label(key), words(read(request, source))]),
    technical: Object.entries(display.technical).map(([key, source]) => [label(key), technical(read(request, source))]),
  };
}

export function displayRefusal(display, code) {
  return Object.hasOwn(display.refusals, code) ? display.refusals[code] : null;
}
