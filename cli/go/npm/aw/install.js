"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const PLATFORMS = {
  "linux x64":    { pkg: "@awebai/aw-linux-x64",      bin: "bin/aw" },
  "linux arm64":  { pkg: "@awebai/aw-linux-arm64",     bin: "bin/aw" },
  "darwin x64":   { pkg: "@awebai/aw-darwin-x64",      bin: "bin/aw" },
  "darwin arm64": { pkg: "@awebai/aw-darwin-arm64",     bin: "bin/aw" },
  "win32 x64":    { pkg: "@awebai/aw-windows-x64",     bin: "bin/aw.exe" },
  "win32 arm64":  { pkg: "@awebai/aw-windows-arm64",   bin: "bin/aw.exe" },
};

function main() {
  const key = `${process.platform} ${os.arch()}`;
  const platform = PLATFORMS[key];

  if (!platform) {
    console.error(`[aw] Warning: unsupported platform ${key}, bin/aw JS wrapper will be used`);
    return;
  }

  // Locate the platform binary
  let binPath;
  try {
    binPath = require.resolve(`${platform.pkg}/${platform.bin}`);
  } catch {
    // Platform package not installed (--no-optional). Try direct npm install as fallback.
    try {
      console.error(`[aw] Platform package not found, attempting direct install of ${platform.pkg}...`);
      const version = require(path.join(__dirname, "package.json")).version;
      const installDir = path.join(__dirname, "npm-install");
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, "package.json"), "{}");
      execFileSync("npm", [
        "install", "--loglevel=error", "--prefer-offline",
        "--no-audit", "--progress=false",
        `${platform.pkg}@${version}`
      ], { cwd: installDir, stdio: "pipe" });
      binPath = path.join(installDir, "node_modules", platform.pkg, platform.bin);
    } catch (e) {
      // Final fallback: try downloading the tarball directly from npm registry
      try {
        binPath = downloadFromRegistry(platform, key);
      } catch {
        console.error(`[aw] Warning: could not install platform package. The JS wrapper will be used.`);
        return;
      }
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
    } catch {
      // Fall through: leave JS wrapper in place
    }
  }

  // Verify the binary is accessible via the JS wrapper
  try {
    execFileSync(binPath, ["version"], { stdio: "pipe" });
  } catch {
    // Binary exists but couldn't run version check — that's OK
  }
}

function downloadFromRegistry(platform, key) {
  const version = require(path.join(__dirname, "package.json")).version;
  const suffix = platform.pkg.replace("@awebai/", "");
  const url = `https://registry.npmjs.org/@awebai/${suffix}/-/${suffix}-${version}.tgz`;

  console.error(`[aw] Downloading ${url}...`);

  // Synchronous download using child_process
  const tgzPath = path.join(__dirname, `${suffix}.tgz`);
  execFileSync("node", ["-e", [
    'const https = require("https");',
    'const fs = require("fs");',
    "function fetch(url) {",
    "  return new Promise((resolve, reject) => {",
    "    https.get(url, res => {",
    "      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location)",
    "        return fetch(res.headers.location).then(resolve, reject);",
    "      if (res.statusCode !== 200)",
    '        return reject(new Error("HTTP " + res.statusCode));',
    "      const chunks = [];",
    '      res.on("data", c => chunks.push(c));',
    '      res.on("end", () => resolve(Buffer.concat(chunks)));',
    "    }).on(\"error\", reject);",
    "  });",
    "}",
    `fetch(${JSON.stringify(url)}).then(buf => fs.writeFileSync(${JSON.stringify(tgzPath)}, buf));`,
  ].join("\n")], { stdio: "pipe" });

  // Extract the binary from the tarball
  const tar = execFileSync("tar", ["tzf", tgzPath], { stdio: "pipe" }).toString();
  const binEntry = tar.split("\n").find(e => e.endsWith(platform.bin.split("/").pop()));
  if (!binEntry) throw new Error("Binary not found in tarball");

  const extractDir = path.join(__dirname, "npm-extract");
  fs.mkdirSync(extractDir, { recursive: true });
  execFileSync("tar", ["xzf", tgzPath, "-C", extractDir], { stdio: "pipe" });

  const extractedBin = path.join(extractDir, binEntry);
  const targetBin = path.join(__dirname, "bin", process.platform === "win32" ? "aw.exe" : "aw");
  fs.copyFileSync(extractedBin, targetBin);
  fs.chmodSync(targetBin, 0o755);

  // Cleanup
  try { fs.unlinkSync(tgzPath); } catch {}
  try { fs.rmSync(extractDir, { recursive: true }); } catch {}

  return targetBin;
}

function isYarn() {
  const agent = process.env.npm_config_user_agent || "";
  return /\byarn\//.test(agent);
}

try {
  main();
} catch (e) {
  // Postinstall must never fail the overall install
  console.error(`[aw] Warning: postinstall encountered an error: ${e.message}`);
}
