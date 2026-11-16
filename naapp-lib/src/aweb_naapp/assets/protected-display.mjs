// The words a person sees for one frozen request, filled from the operation
// definition's display. operation_display.py fills the same templates the
// same way for mail, the owner page and the CLI, so every surface says the same.
import { canonical } from "./canonical-json.mjs";

const refused = () => { throw new Error("handoff_refused"); };
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);

function teamName(teamId) {
  if (typeof teamId !== "string" || teamId.split(":").length !== 2 || !teamId.split(":")[0]) refused();
  return teamId.split(":")[0];
}

// A frozen target kind in the words the owner page uses.
const kinds = {"agent": "agent", "kind not verified": "agent or person not confirmed"};

// "|team" shows a team id ("name:domain") by its name, as the owner page does;
// "|kind" names a frozen target kind; "|period" names a window in seconds.
// Any other value refuses.
function period(seconds) {
  if (!Number.isSafeInteger(seconds) || seconds <= 0) refused();
  return {3600: "hour", 86400: "day"}[seconds] ?? `${seconds} seconds`;
}

function formatted(value, formatter) {
  if (formatter === "period") return period(value);
  if (formatter === "kind") {
    if (typeof value !== "string" || !Object.hasOwn(kinds, value)) refused();
    return kinds[value];
  }
  if (formatter !== "team") refused();
  return Array.isArray(value) ? value.map(teamName) : teamName(value);
}

function read(request, source) {
  const bar = source.indexOf("|");
  const pointer = bar < 0 ? source : source.slice(0, bar);
  let value = request;
  for (const part of pointer.split("/").slice(1)) {
    if (!object(value) || !Object.hasOwn(value, part)) refused();
    value = value[part];
  }
  return bar < 0 ? value : formatted(value, source.slice(bar + 1));
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

// The requester, by the subject's frozen name when it is that subject.
function requester(display, request) {
  const who = words(read(request, "/requester"));
  const [subject, name] = display.requester_name;
  return read(request, subject) === who ? words(read(request, name)) : who;
}

export function renderDisplay(display, request) {
  return {
    title: fill(display.title, request),
    consequences: display.consequences.map(line => fill(line, request)),
    names: Object.entries(display.names).map(([key, source]) => [label(key), words(read(request, source))]),
    technical: Object.entries(display.technical).map(([key, source]) => [label(key), technical(read(request, source))]),
    ...(display.requester_name ? {requester: requester(display, request)} : {}),
  };
}

export function displayRefusal(display, code) {
  return Object.hasOwn(display.refusals, code) ? display.refusals[code] : null;
}
