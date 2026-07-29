#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

function fail(message) {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(1);
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) fail(`${name} is required`);
  return process.argv[index + 1];
}

function git(args, options = {}) {
  try {
    const output = execFileSync("git", args, {
      encoding: "utf8",
      stdio: options.capture === false ? "inherit" : ["ignore", "pipe", "pipe"],
    });
    return typeof output === "string" ? output.trim() : "";
  } catch (error) {
    const stderr = String(error?.stderr || "").trim();
    fail(`git ${args[0]} failed${stderr ? `: ${stderr}` : ""}`);
  }
}

const requestedPinPath = resolve(argument("--pin-file"));
if (!existsSync(requestedPinPath)) fail(`OAS pin does not exist: ${requestedPinPath}`);
const pinPath = realpathSync(requestedPinPath);
const target = resolve(argument("--target"));
let pin;
try {
  pin = JSON.parse(readFileSync(pinPath, "utf8"));
} catch (error) {
  fail(`cannot parse OAS pin ${pinPath}: ${error.message}`);
}

const repository = String(pin.repository || "").trim();
const commit = String(pin.commit || "").trim();
if (!repository) fail(`OAS pin ${pinPath} has no repository`);
if (!/^[0-9a-f]{40}$/.test(commit)) {
  fail(`OAS pin ${pinPath} must contain a full lowercase 40-hex commit`);
}

const markerName = "aweb-oas-pin-cache.json";
if (existsSync(target)) {
  if (lstatSync(target).isSymbolicLink()) fail(`refusing symlinked OAS cache ${target}`);
  const marker = resolve(target, ".git", markerName);
  if (!existsSync(marker)) {
    fail(`refusing to reset unowned directory ${target}; cache marker is missing`);
  }
  let ownership;
  try {
    ownership = JSON.parse(readFileSync(marker, "utf8"));
  } catch {
    fail(`refusing OAS cache ${target}; cache marker is unreadable`);
  }
  if (ownership.repository !== repository) {
    fail(`refusing OAS cache ${target}; cache marker names a different repository`);
  }
} else {
  mkdirSync(dirname(target), { recursive: true });
  mkdirSync(target);
  git(["init", "-q", target]);
  writeFileSync(
    resolve(target, ".git", markerName),
    JSON.stringify({ repository }) + "\n",
    { encoding: "utf8", mode: 0o600 },
  );
}

const topLevel = realpathSync(git(["-C", target, "rev-parse", "--show-toplevel"]));
if (topLevel !== realpathSync(target)) {
  fail(`refusing OAS cache whose git top-level differs from its target: ${target}`);
}

let origin = "";
try {
  origin = execFileSync("git", ["-C", target, "remote", "get-url", "origin"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
} catch {
  git(["-C", target, "remote", "add", "origin", repository]);
  origin = repository;
}
if (origin !== repository) {
  fail(`refusing OAS cache ${target}; origin is ${origin}, expected ${repository}`);
}

let hasCommit = true;
try {
  execFileSync("git", ["-C", target, "cat-file", "-e", `${commit}^{commit}`], {
    stdio: "ignore",
  });
} catch {
  hasCommit = false;
}
if (!hasCommit) {
  git(["-C", target, "fetch", "--depth=1", "--no-tags", "origin", commit], {
    capture: false,
  });
}

git(["-C", target, "checkout", "--detach", "--force", commit]);
git(["-C", target, "reset", "--hard", commit]);
git(["-C", target, "clean", "-ffdqx"]);

const head = git(["-C", target, "rev-parse", "HEAD"]);
const status = git(["-C", target, "status", "--porcelain"]);
if (head !== commit) fail(`prepared OAS checkout is ${head}, expected ${commit}`);
if (status) fail(`prepared OAS checkout is dirty: ${status}`);

process.stdout.write(`Prepared pinned OAS ${commit} at ${target}\n`);
