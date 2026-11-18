"use strict";
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const { NativeBinary, hostPlatform, fallbackBinaryPath, resolveNativeBinary } = require("./platform");

function main() {
  const platform = hostPlatform();

  // Locate the platform binary
  let binPath;
  try {
    binPath = resolveNativeBinary({platform, binary:NativeBinary.AW});
  } catch (error) {
    if (error.code !== "MODULE_NOT_FOUND" && error.code !== "ENOENT") throw error;
    // Platform package not installed (--no-optional). Try direct npm install as fallback.
    try {
      console.error(`[aw] Platform package not found, attempting direct install of ${platform.pkg}...`);
      const version = require(path.join(__dirname, "package.json")).version;
      const installDir = path.join(__dirname, "npm-install");
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, "package.json"), "{}");
      execFileSync("npm", [
        "install", "--loglevel=error", "--prefer-offline",
        "--no-audit", "--progress=false", "--ignore-scripts",
        `${platform.pkg}@${version}`
      ], { cwd: installDir, stdio: "pipe" });
      binPath = fallbackBinaryPath({platform, binary:NativeBinary.AW});
    } catch (e) {
      throw new Error(`Could not fetch verified ${platform.pkg} with npm. Retry: npm install @awebai/aw --force. ${e.message}`);
    }
  }

  // On Unix (not Yarn), try to hard-link the native binary over the JS launcher
  const toPath = path.join(__dirname, "bin", "aw");
  if (process.platform !== "win32" && !isYarn()) {
    try {
      const tempPath = toPath + ".tmp";
      fs.linkSync(binPath, tempPath);
      fs.renameSync(tempPath, toPath);
      return; // Success: bin/aw is now the native binary
    } catch (error) {
      console.error(`[aw] Native linking unavailable (${error.message}); using the JavaScript launcher.`);
    }
  }


}

function isYarn() {
  const agent = process.env.npm_config_user_agent || "";
  return /\byarn\//.test(agent);
}

try {
  main();
} catch (e) {
  console.error(`[aw] Installation refused: ${e.message}`);
  process.exitCode = 1;
}
