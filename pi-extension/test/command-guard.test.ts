import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import awebPiExtension, { tmuxCommandGuardReason } from "../src/index.js";

test("tmux command guard detects direct and inline-trap teardown", () => {
  const blocked = [
    "tmux kill-server",
    "tmux kill-serv",
    "TMUX_TMPDIR=/tmp/test tmux -L dogfood kill-session -t test",
    "TMUX_TMPDIR=/tmp/test tmux kill-sess -t test",
    "trap 'AWEB_TMUX_TMPDIR=/tmp/wrong tmux kill-server' EXIT",
    "aw team up --session test --recreate --force-kill",
  ];
  for (const command of blocked) {
    assert.match(tmuxCommandGuardReason(command) ?? "", /Blocked/);
  }

  const allowed = [
    "tmux list-sessions",
    "TMUX_TMPDIR=/tmp/test tmux new-session -d -s test",
    "aw team up --session test --no-attach",
    "bash scripts/migrate-agent-tmux.sh --dry-run --team cli",
  ];
  for (const command of allowed) {
    assert.equal(tmuxCommandGuardReason(command), undefined, command);
  }
});

test("aweb extension blocks destructive pi bash tool calls", async () => {
  let toolCallHandler: ((event: { toolName: string; input: unknown }) => unknown) | undefined;
  const pi = {
    on(name: string, handler: (event: { toolName: string; input: unknown }) => unknown) {
      if (name === "tool_call") toolCallHandler = handler;
    },
  } as unknown as ExtensionAPI;

  awebPiExtension(pi);
  assert.ok(toolCallHandler, "tool_call guard was not registered");
  assert.deepEqual(
    await toolCallHandler({ toolName: "bash", input: { command: "tmux kill-server" } }),
    {
      block: true,
      reason: "Blocked tmux kill-server. Agent runtimes may not tear down tmux; use a committed, reviewed, guard-enforced migration or dogfood harness.",
    },
  );
  assert.equal(
    await toolCallHandler({ toolName: "read", input: { path: "notes.md" } }),
    undefined,
  );
});
