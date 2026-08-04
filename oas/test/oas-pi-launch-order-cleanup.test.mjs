import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";
import {
  executionCheck,
  finalizeExecutionArtifacts,
  isolatedExecutionEnvironment,
} from "../../scripts/check-oas-pi-launch-order.mjs";

const REPO_ROOT = resolve(new URL("../..", import.meta.url).pathname);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryExecutionTree() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oas-pi-order-cleanup-")));
  temporaryDirectories.push(base);
  const authPath = join(base, "home", ".pi", "agent", "auth.json");
  const tmuxDirectory = join(base, "tmux");
  mkdirSync(tmuxDirectory, { recursive: true });
  mkdirSync(join(base, "home", ".pi", "agent"), { recursive: true });
  writeFileSync(authPath, "throwaway-secret\n", { mode: 0o600 });
  return { base, authPath, tmuxDirectory };
}

function fakeTmux(responses) {
  const calls = [];
  return {
    calls,
    run(args, env) {
      calls.push({ args, env });
      const response = responses.shift();
      assert.ok(response, `unexpected tmux call: ${args.join(" ")}`);
      return response;
    },
  };
}

function tmuxResult(status, stdout = "", stderr = "") {
  return { status, stdout, stderr };
}

test("real execution drops inherited TMUX while preserving the isolated socket selection", () => {
  const env = isolatedExecutionEnvironment(
    { PATH: "/guard:/bin", TMUX: "/private/tmp/live/default,1,2", HOME: "/ambient" },
    { HOME: "/throwaway", TMUX_TMPDIR: "/throwaway/tmux" },
  );

  assert.equal(env.TMUX, undefined);
  assert.equal(env.TMUX_TMPDIR, "/throwaway/tmux");
  assert.equal(env.HOME, "/throwaway");
  assert.equal(env.PATH, "/guard:/bin");
});

test("the production execution route passes one TMUX-free isolated environment to spawn and cleanup", () => {
  const authDirectory = realpathSync(mkdtempSync(join(tmpdir(), "aweb-oas-pi-order-auth-")));
  temporaryDirectories.push(authDirectory);
  const authSource = join(authDirectory, "auth.json");
  writeFileSync(authSource, "throwaway-auth\n", { mode: 0o600 });
  const tmux = fakeTmux([]);
  let spawnEnv;
  tmux.run = (args, env) => {
    tmux.calls.push({ args, env });
    return tmuxResult(1, "", `error connecting to ${join(env.TMUX_TMPDIR, "default")} (No such file or directory)`);
  };

  executionCheck({
    ambientEnv: {
      ...process.env,
      PATH: `${join(REPO_ROOT, "scripts", "guard-bin")}:${process.env.PATH}`,
      TMUX: "/private/tmp/live/default,1,2",
    },
    authSource,
    spawnExecutionProbe(_fixture, env) {
      spawnEnv = env;
      temporaryDirectories.push(dirname(env.TMUX_TMPDIR));
      const home = join(dirname(env.TMUX_TMPDIR), "spawned");
      mkdirSync(home, { recursive: true });
      writeFileSync(join(home, "instance.json"), JSON.stringify({
        command: "pi @TASK.md --append-system-prompt",
      }));
      const session = join(env.PI_CODING_AGENT_DIR, "sessions", "probe.jsonl");
      writeFileSync(session, JSON.stringify({
        message: { role: "assistant", content: [{ type: "text", text: "OAS_PI_LAUNCH_ORDER_OK" }] },
      }) + "\n");
      return { home };
    },
    runTmux: tmux.run,
    reportPass() {},
  });

  assert.equal(spawnEnv.TMUX, undefined, "production spawn inherited the caller's live tmux socket");
  assert.match(spawnEnv.TMUX_TMPDIR, /aweb-oas-pi-order-execution-/);
  assert.equal(tmux.calls.length, 1);
  assert.equal(tmux.calls[0].env, spawnEnv, "cleanup did not receive the exact isolated spawn environment");
  assert.equal(existsSync(dirname(spawnEnv.TMUX_TMPDIR)), false, "established cleanup left the execution tree behind");
  assert.equal(existsSync(authSource), true, "the host auth fixture must not be deleted");
});

test("cleanup proves exact-session removal before deleting the isolated execution tree", () => {
  const tree = temporaryExecutionTree();
  const tmux = fakeTmux([
    tmuxResult(0, "other\nprobe\n"),
    tmuxResult(0),
    tmuxResult(0, "other\n"),
  ]);
  const env = isolatedExecutionEnvironment(
    { PATH: "/guard:/bin", TMUX: "/private/tmp/live/default,1,2" },
    { TMUX_TMPDIR: tree.tmuxDirectory },
  );

  finalizeExecutionArtifacts({
    ...tree,
    session: "probe",
    env,
    tmuxAttempted: true,
    runTmux: tmux.run,
  });

  assert.equal(existsSync(tree.base), false);
  assert.deepEqual(tmux.calls.map((call) => call.args), [
    ["list-sessions", "-F", "#{session_name}"],
    ["kill-session", "-t", "=probe"],
    ["list-sessions", "-F", "#{session_name}"],
  ]);
  assert.ok(tmux.calls.every((call) => call.env.TMUX === undefined));
  assert.ok(tmux.calls.every((call) => call.env.TMUX_TMPDIR === tree.tmuxDirectory));
});

test("an ambiguous tmux inspection removes copied auth but retains socket retry evidence", () => {
  const tree = temporaryExecutionTree();
  const tmux = fakeTmux([tmuxResult(1, "", "permission denied")]);
  const env = isolatedExecutionEnvironment(
    { PATH: "/guard:/bin", TMUX: "/private/tmp/live/default,1,2" },
    { TMUX_TMPDIR: tree.tmuxDirectory },
  );

  assert.throws(
    () => finalizeExecutionArtifacts({
      ...tree,
      session: "probe",
      env,
      tmuxAttempted: true,
      runTmux: tmux.run,
    }),
    /retained isolated tmux evidence.*retry manually/s,
  );
  assert.equal(existsSync(tree.authPath), false, "copied model auth must never be retained");
  assert.equal(existsSync(tree.base), true, "retry evidence must survive an unestablished teardown");
  assert.equal(existsSync(tree.tmuxDirectory), true, "the isolated socket directory must remain reachable");
});

test("a failed exact-session kill retains the socket tree instead of claiming cleanup", () => {
  const tree = temporaryExecutionTree();
  const tmux = fakeTmux([
    tmuxResult(0, "probe\n"),
    tmuxResult(1, "", "simulated kill failure"),
  ]);
  const env = isolatedExecutionEnvironment({}, { TMUX_TMPDIR: tree.tmuxDirectory });

  assert.throws(
    () => finalizeExecutionArtifacts({
      ...tree,
      session: "probe",
      env,
      tmuxAttempted: true,
      runTmux: tmux.run,
    }),
    /simulated kill failure.*retained isolated tmux evidence/s,
  );
  assert.equal(existsSync(tree.authPath), false);
  assert.equal(existsSync(tree.tmuxDirectory), true);
});

test("a known absent isolated server is established cleanup, not an ambiguous failure", () => {
  const tree = temporaryExecutionTree();
  const tmux = fakeTmux([
    tmuxResult(1, "", `error connecting to ${join(tree.tmuxDirectory, "default")} (No such file or directory)`),
  ]);
  const env = isolatedExecutionEnvironment({}, { TMUX_TMPDIR: tree.tmuxDirectory });

  finalizeExecutionArtifacts({
    ...tree,
    session: "probe",
    env,
    tmuxAttempted: true,
    runTmux: tmux.run,
  });
  assert.equal(existsSync(tree.base), false);
});
