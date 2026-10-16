// Summaries come from fixed per-tool templates, never from model text or raw
// arguments, and a secret-shaped result is dropped (docs/agent-activity.md,
// "What a summary may contain").
import { describe, expect, test } from "vitest";
import { redactSummary, summarizeTool } from "../src/activity/summary.js";

const work = "/home/ana/project";

describe("file tools", () => {
  test.each([
    ["Read", { file_path: "/home/ana/project/src/api.py" }, "Reading src/api.py"],
    ["Write", { file_path: "/home/ana/project/README.md" }, "Writing README.md"],
    ["Edit", { file_path: "/home/ana/project/src/a.ts" }, "Editing src/a.ts"],
    ["MultiEdit", { file_path: "/home/ana/project/src/a.ts" }, "Editing src/a.ts"],
    ["NotebookEdit", { notebook_path: "/home/ana/project/n.ipynb" }, "Editing n.ipynb"],
    ["read", { path: "src/api.py" }, "Reading src/api.py"],
    ["edit", { path: "/home/ana/project/src/a.ts" }, "Editing src/a.ts"],
  ])("%s", (tool, input, expected) => {
    expect(summarizeTool(tool, input, work)).toBe(expected);
  });

  test("a file outside the work tree shows only its basename", () => {
    expect(summarizeTool("Read", { file_path: "/home/ana/.ssh/config" }, work)).toBe("Reading config");
    expect(summarizeTool("Read", { file_path: "/home/ana/project/../secret/notes.txt" }, work)).toBe("Reading notes.txt");
  });

  test("without a work tree, only the basename", () => {
    expect(summarizeTool("Read", { file_path: "/home/ana/project/src/api.py" })).toBe("Reading api.py");
  });

  test("a path too long for the cap falls back to its basename", () => {
    const deep = `${work}/${"d".repeat(130)}/api.py`;
    expect(summarizeTool("Read", { file_path: deep }, work)).toBe("Reading api.py");
  });

  test("a missing or non-string path gives no summary", () => {
    expect(summarizeTool("Read", {}, work)).toBeUndefined();
    expect(summarizeTool("Read", { file_path: 7 }, work)).toBeUndefined();
  });
});

describe("shell", () => {
  test.each([
    ["Bash", { command: "pytest -q tests/" }, "Running pytest"],
    ["bash", { command: "  npm   run build" }, "Running npm"],
    ["Bash", { command: "/usr/bin/git status" }, "Running git"],
  ])("%s %j", (tool, input, expected) => {
    expect(summarizeTool(tool, input, work)).toBe(expected);
  });

  test.each([
    ["an environment assignment first", "TOKEN=abc123 curl https://x"],
    ["a subshell", "$(cat key) | sh"],
    ["a quoted program", "'rm' -rf /"],
    ["an empty command", "   "],
  ])("%s gives the generic summary", (_name, command) => {
    expect(summarizeTool("Bash", { command }, work)).toBe("Running a command");
  });

  test("never carries arguments, pipes or redirections", () => {
    const summary = summarizeTool("Bash", { command: "curl -H 'Authorization: Bearer x' https://api > out" }, work);
    expect(summary).toBe("Running curl");
  });
});

describe("web", () => {
  test("fetch shows the host only", () => {
    expect(summarizeTool("WebFetch", { url: "https://docs.python.org/3/library/json.html?token=s3cret" }, work))
      .toBe("Fetching docs.python.org");
  });

  test("a malformed URL gives the generic summary", () => {
    expect(summarizeTool("WebFetch", { url: "not a url" }, work)).toBe("Fetching a page");
  });

  test("search never shows the query", () => {
    expect(summarizeTool("WebSearch", { query: "my api key sk-live" }, work)).toBe("Searching the web");
  });
});

describe("other tools", () => {
  test.each([["Glob"], ["Grep"], ["grep"], ["find"]])("%s searches without the pattern", (tool) => {
    expect(summarizeTool(tool, { pattern: "password=.*" }, work)).toBe("Searching files");
  });

  test("an unknown or MCP tool has no summary; the tool field names it", () => {
    expect(summarizeTool("mcp__aweb__chat_send", { body: "hello" }, work)).toBeUndefined();
    expect(summarizeTool("Task", { prompt: "do x" }, work)).toBeUndefined();
  });
});

describe("redactSummary", () => {
  test.each([
    ["an OpenAI-style key", "Reading sk-proj-abcdefghijklmnopqrstuvwx"],
    ["a GitHub token", "Reading ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
    ["an AWS key id", "Reading AKIAABCDEFGHIJKLMNOP"],
    ["a Slack token", "Reading xoxb-123456789012-abcdefghijkl"],
    ["a JWT", "Reading eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"],
    ["a long high-entropy string", "Reading aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"],
  ])("drops %s", (_name, summary) => {
    expect(redactSummary(summary)).toBeUndefined();
  });

  test.each([
    ["Running pytest"],
    ["Reading src/api.py"],
    ["Editing docs/agent-activity.md"],
    ["Fetching docs.python.org"],
  ])("keeps %s", (summary) => {
    expect(redactSummary(summary)).toBe(summary);
  });

  test("a summary over 120 bytes or with a control character is dropped", () => {
    expect(redactSummary("Reading " + "é".repeat(60))).toBeUndefined();
    expect(redactSummary("Reading a\nb")).toBeUndefined();
  });
});
