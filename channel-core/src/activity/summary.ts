// Activity summaries (docs/agent-activity.md, "What a summary may contain").
// A summary comes from a fixed per-tool template, never from model text or raw
// tool arguments: a command line or a URL can carry a bearer token. The
// redactor is the second line of defence, not the first.
import { basename, relative, resolve, sep } from "node:path";

export const SUMMARY_MAX_BYTES = 120;

const FILE_VERBS: Record<string, string> = {
  Read: "Reading",
  read: "Reading",
  Write: "Writing",
  write: "Writing",
  Edit: "Editing",
  MultiEdit: "Editing",
  NotebookEdit: "Editing",
  edit: "Editing",
};
const SHELL_TOOLS = new Set(["Bash", "bash"]);
const SEARCH_TOOLS = new Set(["Glob", "Grep", "grep", "find"]);
const PROGRAM = /^[A-Za-z0-9_.\/+-]+$/;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const SECRET_SHAPES = [
  /\bsk-[A-Za-z0-9_-]{16,}/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bglpat-[A-Za-z0-9_-]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
];
const LONG_TOKEN = /[A-Za-z0-9+/=_-]{32,}/g;

function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

function looksHighEntropy(token: string): boolean {
  return /[a-z]/.test(token) && /[A-Z]/.test(token) && /[0-9]/.test(token);
}

/** The summary, or undefined when it is too long, multi-line or secret-shaped. */
export function redactSummary(summary: string): string | undefined {
  if (!summary || byteLength(summary) > SUMMARY_MAX_BYTES || CONTROL.test(summary)) return undefined;
  if (SECRET_SHAPES.some(shape => shape.test(summary))) return undefined;
  if ((summary.match(LONG_TOKEN) ?? []).some(looksHighEntropy)) return undefined;
  return summary;
}

function displayPath(path: string, workRoot: string | undefined): string {
  const name = basename(path);
  if (!workRoot) return name;
  const root = resolve(workRoot);
  const absolute = resolve(root, path);
  if (!absolute.startsWith(root + sep)) return name;
  return relative(root, absolute);
}

function fileSummary(verb: string, input: Record<string, unknown>, workRoot: string | undefined): string | undefined {
  const path = [input.file_path, input.notebook_path, input.path].find(value => typeof value === "string" && value);
  if (typeof path !== "string") return undefined;
  const shown = `${verb} ${displayPath(path, workRoot)}`;
  return byteLength(shown) <= SUMMARY_MAX_BYTES ? shown : `${verb} ${basename(path)}`;
}

function shellSummary(input: Record<string, unknown>): string {
  const command = typeof input.command === "string" ? input.command.trim() : "";
  const first = command.split(/\s+/, 1)[0] ?? "";
  if (!first || first.includes("=") || !PROGRAM.test(first)) return "Running a command";
  const program = basename(first);
  return program ? `Running ${program}` : "Running a command";
}

function fetchSummary(input: Record<string, unknown>): string {
  try {
    const host = new URL(String(input.url)).hostname;
    return host ? `Fetching ${host}` : "Fetching a page";
  } catch {
    return "Fetching a page";
  }
}

/** The template summary for one tool call, or undefined when none applies. */
export function summarizeTool(tool: string, input: unknown, workRoot?: string): string | undefined {
  const args = input !== null && typeof input === "object" ? (input as Record<string, unknown>) : {};
  let summary: string | undefined;
  if (FILE_VERBS[tool]) summary = fileSummary(FILE_VERBS[tool], args, workRoot);
  else if (SHELL_TOOLS.has(tool)) summary = shellSummary(args);
  else if (tool === "WebFetch") summary = fetchSummary(args);
  else if (tool === "WebSearch") summary = "Searching the web";
  else if (SEARCH_TOOLS.has(tool)) summary = "Searching files";
  return summary === undefined ? undefined : redactSummary(summary);
}
